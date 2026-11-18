# Chia Kritik Zafiyet Fuzz Altyapısı

HackerOne Chia Network kapsamındaki (chiapos, pos2/chia-pos2, clvm_rs) kritik
sınıfı zafiyetler (bellek güvenliği / uzak crash) için hazır **libFuzzer +
AddressSanitizer + UBSan** fuzz paketi. Bulgular (crash dosyaları) HackerOne
raporuna eklenecek şekilde toplanır.

> **Hukuki/test sınırı:** Tüm koşumlar yereldir/CI'dadır; canlı Chia
> altyapısına veya başka hiçbir hedefe trafik gönderilmez.

---

## Neden bu hedefler (araştırma bağlamı)

2.7.1 sonrası yapılan kaynak denetiminde kritik bulgu bulunamadı (bkz.
`kritik-avi-negatif-sonuc.md`). Kritik sınıfı bulguların çıktığı yer, ağdan
gelen veriyi işleyen **C++** kodudur ve bu yalnızca fuzz ile güvenilir şekilde
taranabilir:

| Hedef | Neden kritik yol |
|---|---|
| `pos2` C ABI: `validate_proof` | Her full node, ağdan gelen v2 PoSpace'i bu fonksiyonla doğrular. Burada bellek hatası = ağ çapında crash/RCE. |
| `pos2` C ABI: `proof_to_quality_string` | Blok hash'i alınırken çağrılır (PanicException bulgumuzun altındaki C girişi). |
| `pos2` C ABI: `solve_partial_proof` | Solver servisinin ağdan gelen `SolverInfo` ile çağırdığı giriş. |
| `chiapos` v1: `Verifier::ValidateProof` | Her full node, ağdan gelen v1 PoSpace'i bununla doğrular (2021 kod tabanı). |
| `clvm_rs` (seçili hedefler) | Konsensüs-kritik CLVM yorumlayıcısı; `serde_2026_panic` hedefi zaten panic aramak için var. |

### Kritik boşluk: upstream fuzz hedefleri ham değerleri kırpıyor

Upstream `pos2/crates/chia-pos2/fuzz/fuzz_targets/validate.rs` **k'yı 12..=28'e,
strength'i 2..=64'e kırpıyor**. Oysa ağ yolu ham `u8` (0..=255) veriyor ve C
ABI yalnızca tek/aralık-dışı k'yı reddediyor. `k=29..255`, `strength=255`,
`k=0` gibi malformed değerler upstream fuzzer'ında **hiç üretilmiyor**. Bu
paketteki `pos2_validate_raw` / `pos2_solve_raw` / `pos2_quality_raw`
harness'ları C ABI'yi **ham değerlerle** besliyor — aradığımız hata sınıfının
en olası olduğu yer burası.

---

## Yol A — GitHub Actions (önerilen; yerel derleyici GEREKMEZ)

Bu Windows makinede derleyici yok ve WSL/Docker kullanılamıyor; koşum GitHub'ın
ücretsiz Ubuntu runner'larında yapılır.

1. Bir GitHub repo'su oluştur (ör. `chia-fuzz`), **public** olsun (ücretsiz
   dakika kullanımı için).
2. Bu `fuzz/` dizininin İÇERİĞİNİ repo köküne kopyala — yani repo kökünde
   `harnesses/`, `seeds/`, `.github/`, `build.sh`, `run.sh` bulunmalı
   (`fuzz/.github/workflows/chia-fuzz.yml` otomatik olarak repo kökündeki
   `.github/workflows/` altına yerleşir).
3. Push et → GitHub'da **Actions** sekmesi → `chia-fuzz` → **Run workflow**
   (varsayılan: hedef başına 300 sn; gece koşumu için `fuzz_seconds: 28800`).
4. Bitince işin altındaki **fuzz-artifacts** zip'ini indir → `crash-*`,
   `timeout-*`, `oom-*` dosyaları içinde.

İpucu: İlk koşum ~40-60 dk sürer (derleme dahil). `schedule` satırını aktifleştirirsen
her hafta otomatik koşar; cache sayesinde sonraki koşumlar çok daha hızlı olur.

## Yol B — Bare Linux / WSL2 / VPS (Docker'sız, elle)

Herhangi bir Linux makinede (veya WSL2'nin açık olduğu bir Windows'ta):

```bash
sudo apt-get update && sudo apt-get install -y clang cmake build-essential python3 pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly --profile minimal
source "$HOME/.cargo/env" && cargo install cargo-fuzz

mkdir -p ~/chia-src && cd ~/chia-src
git clone https://github.com/Chia-Network/pos2-chip.git pos2
(cd pos2 && git fetch --depth 1 origin cdabddfa5fd993d9f715635973dd758e7e2c7718 && git checkout -f cdabddfa5fd993d9f715635973dd758e7e2c7718)
git clone https://github.com/Chia-Network/chiapos.git chiapos
(cd chiapos && git fetch --depth 1 origin 254dc99bfc2873ef8c592868e54ed4ece022f50c && git checkout -f 254dc99bfc2873ef8c592868e54ed4ece022f50c)
git clone https://github.com/Chia-Network/clvm_rs.git clvm_rs
(cd clvm_rs && git fetch --depth 1 origin 59d7e870dd4b4224309d8d0e7e952f186eac7eab && git checkout -f 59d7e870dd4b4224309d8d0e7e952f186eac7eab)

# fuzz paketini ~/chia-fuzz'a kopyala, sonra:
FUZZ_DIR=$HOME/chia-fuzz SRC_DIR=$HOME/chia-src OUT_DIR=$HOME/chia-out bash $HOME/chia-fuzz/build.sh
FUZZ_DIR=$HOME/chia-fuzz SRC_DIR=$HOME/chia-src OUT_DIR=$HOME/chia-out FUZZ_SECONDS=28800 bash $HOME/chia-fuzz/run.sh
```

Bulgular: `$HOME/chia-out/artifacts/<hedef>/crash-*`.

## Yol C — Docker (eski yöntem, opsiyonel)

```bash
docker build -t chia-fuzz ./fuzz
docker run --rm -v chia-artifacts:/out/artifacts chia-fuzz
docker run --rm -e FUZZ_SECONDS=28800 -v chia-artifacts:/out/artifacts chia-fuzz
```

---

## Paket içeriği

```
fuzz/
├── .github/workflows/chia-fuzz.yml   # Yol A: CI workflow'u (pinned commit'ler, artifact yükleme)
├── Dockerfile                        # Yol C (opsiyonel)
├── build.sh                          # C++ harness + Rust hedef derlemesi (env ile yönlendirilebilir, toleranslı)
├── run.sh                            # tüm hedefleri koşar, artifact toplar, özet basar
├── harnesses/
│   ├── pos2_validate_raw.cpp         # C ABI validate_proof — HAM k/strength (ağ birebir)
│   ├── pos2_solve_raw.cpp            # C ABI solve_partial_proof — HAM k/strength
│   ├── pos2_quality_raw.cpp          # C ABI proof_to_quality_string — HAM k/strength
│   └── chiapos_validate_v1.cpp       # v1 Verifier::ValidateProof — HAM k/proof_size
└── seeds/
    ├── generate_seeds.py             # 137 seed üretir (aşağıdaki dizinler üretilmiştir)
    ├── pos2-raw/  pos2-validate/  pos2-solver/  pos2-prover/
    ├── chiapos-v1/  clvm/
    └── ...
```

Pinlenen commit'ler (tekrarlanabilirlik):
- pos2-chip: `cdabddfa5fd993d9f715635973dd758e7e2c7718`
- chiapos:   `254dc99bfc2873ef8c592868e54ed4ece022f50c`
- clvm_rs:   `59d7e870dd4b4224309d8d0e7e952f186eac7eab`

## Bulgu triyajı (crash çıktığında)

1. **Tekrar üret:** indirilen artifact ile:
   - CI'da: artifact içindeki `crash-*` dosyasıyla işi yeniden çalıştırmak yerine
     Yol B'deki kurulumu kullan: `$HOME/chia-out/bin/<hedef> <crash-dosyası>`
     (ASAN raporu stack trace verir).
   - Docker'da: `docker run --rm --entrypoint /out/bin/<hedef> chia-fuzz <crash-dosyası>`
2. **Minimize et:** `<hedef> -minimize_crash=1 <crash>` → küçük repro input.
3. **Ağdan tetiklenebilirliği haritala:** crash'i üreten girişi karşılık gelen
   ağ mesajına çevir:
   - `pos2_validate_raw` → `ProofOfSpace` (v2) içinde proof/strength/plot_index
     alanları → `UNFINISHED_BLOCK`/`respond_block` gossip'u;
   - `pos2_quality_raw` → blok hash yolu (her node);
   - `pos2_solve_raw` → `SolverInfo` → solver servisi;
   - `chiapos_validate_v1` → v1 `ProofOfSpace.proof` + `size` → blok gossip'u.
4. **Yerel PoC yaz** (yalnızca yerel; canlı ağa trafik YOK), ardından
   HackerOne'a raporla. Rapor şablonu için `bulgu-01-wallet-v2-pos-panic.md`
   formatını kullan.

## Bilinen sınırlar / sorun giderme

- Build bu Windows ortamında **çalıştırılamadı** (derleyici yok, WSL engelli);
  ilk CI/Linux koşumunda `build.sh` çıktısındaki `FAIL` satırlarına bak. Bir
  hedef derlenmezse diğerleri etkilenmez (toleranslı betik).
- `pos2` C++ harness'ları `patch_fse.py` çıktısını kullanır; FSE derlemesi
  hatasında `pos2-chip` repo'sundaki `README.md` build bölümünü izle.
- `chiapos_validate_v1` FSE yolunda sembol hatası verirse `lib/FiniteStateEntropy`
  kaynak listesini `src/cli.cpp`'deki include'larla karşılaştırıp ekleyin.
- Rust hedefi `prover` her koşumda 10 test plot'u oluşturur (ilk sefer yavaş);
  disk alanı bırakın.
- Önerilen minimum etkili koşum: hedef başına **8-24 saat**
  (`fuzz_seconds: 28800` veya `FUZZ_SECONDS=28800`).
