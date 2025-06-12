import argparse
import bisect
import ipaddress
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

STORE_URL = "https://store.playstation.com/tr-tr/"
DEFAULT_PROFILE = Path(__file__).resolve().parent / "browser_profile"
LOGIN_URL = STORE_URL

# Источники бесплатных турецких прокси (форматы у сервисов могут меняться)
PROXYSCRAPE_URL = (
    "https://api.proxyscrape.com/v4/free-proxy-list/get"
    "?request=display_proxies&country=tr&protocol={proto}"
    "&proxy_format=ipport&format=text&timeout=10000"
)
GEONODE_URL = (
    "https://proxylist.geonode.com/api/proxy-list"
    "?limit=500&page=1&sort_by=lastChecked&sort_type=desc&country=TR"
)
PROXIFLY_URL = (
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main"
    "/proxies/countries/TR/data.txt"
)
SPYS_URL = "https://spys.me/proxy.txt"

# Большие общемировые списки без разбивки по странам: турецкие адреса из них
# отбираются по диапазонам IP Турции из реестра RIPE
_GH = "https://raw.githubusercontent.com/"
BIG_LISTS = [
    (_GH + "TheSpeedX/PROXY-List/master/http.txt", "http"),
    (_GH + "TheSpeedX/PROXY-List/master/socks4.txt", "socks4"),
    (_GH + "TheSpeedX/PROXY-List/master/socks5.txt", "socks5"),
    (_GH + "monosans/proxy-list/main/proxies/http.txt", "http"),
    (_GH + "monosans/proxy-list/main/proxies/socks4.txt", "socks4"),
    (_GH + "monosans/proxy-list/main/proxies/socks5.txt", "socks5"),
    (_GH + "ErcinDedeoglu/proxies/main/proxies/http.txt", "http"),
    (_GH + "ErcinDedeoglu/proxies/main/proxies/socks4.txt", "socks4"),
    (_GH + "ErcinDedeoglu/proxies/main/proxies/socks5.txt", "socks5"),
    (_GH + "roosterkid/openproxylist/main/HTTPS_RAW.txt", "http"),
    (_GH + "roosterkid/openproxylist/main/SOCKS4_RAW.txt", "socks4"),
    (_GH + "roosterkid/openproxylist/main/SOCKS5_RAW.txt", "socks5"),
    (_GH + "vakhov/fresh-proxy-list/master/http.txt", "http"),
    (_GH + "vakhov/fresh-proxy-list/master/socks4.txt", "socks4"),
    (_GH + "vakhov/fresh-proxy-list/master/socks5.txt", "socks5"),
    ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt", "http"),
]
RIPE_TR_URL = (
    "https://stat.ripe.net/data/country-resource-list/data.json"
    "?resource=TR&v4_format=prefix"
)
PROXY_RE = re.compile(r"(?:(https?|socks[45])://)?(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")

# Проверяем страну по HTTPS: так сразу отсеиваются прокси без поддержки CONNECT,
# через которые PS Store всё равно не откроется
IP_CHECK_URL = "https://api.country.is/"


def normalize(entry: str, default_scheme: str = "http") -> str | None:
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None
    if "://" not in entry:
        entry = f"{default_scheme}://{entry}"
    return entry


def from_proxyscrape() -> list[str]:
    out = []
    for proto in ("http", "socks5", "socks4"):
        try:
            r = requests.get(PROXYSCRAPE_URL.format(proto=proto), timeout=15)
            r.raise_for_status()
            for line in r.text.splitlines():
                p = normalize(line, proto)
                if p:
                    out.append(p)
        except Exception as e:
            print(f"  [proxyscrape/{proto}] не удалось: {e}")
    return out


def from_geonode() -> list[str]:
    out = []
    try:
        r = requests.get(GEONODE_URL, timeout=15)
        r.raise_for_status()
        for item in r.json().get("data", []):
            protos = item.get("protocols") or ["http"]
            # приоритет: http/https -> socks5 -> socks4
            for pref in ("http", "https", "socks5", "socks4"):
                if pref in protos:
                    scheme = "http" if pref == "https" else pref
                    out.append(f"{scheme}://{item['ip']}:{item['port']}")
                    break
    except Exception as e:
        print(f"  [geonode] не удалось: {e}")
    return out


def from_proxifly() -> list[str]:
    try:
        r = requests.get(PROXIFLY_URL, timeout=15)
        r.raise_for_status()
        return [p for p in (normalize(l) for l in r.text.splitlines()) if p]
    except Exception as e:
        print(f"  [proxifly] не удалось: {e}")
        return []


def from_spys() -> list[str]:
    try:
        r = requests.get(SPYS_URL, timeout=15)
        r.raise_for_status()
        return [f"http://{m}" for m in re.findall(r"^([\d.]+:\d+) TR-", r.text, re.M)]
    except Exception as e:
        print(f"  [spys.me] не удалось: {e}")
        return []


def tr_ip_filter():
    """Возвращает функцию ip -> bool «адрес из диапазонов Турции» (по данным RIPE)."""
    r = requests.get(RIPE_TR_URL, timeout=30)
    r.raise_for_status()
    nets = sorted(
        (int(n.network_address), int(n.broadcast_address))
        for n in map(ipaddress.ip_network, r.json()["data"]["resources"]["ipv4"])
    )
    starts = [a for a, _ in nets]

    def is_tr(ip: str) -> bool:
        try:
            x = int(ipaddress.ip_address(ip))
        except ValueError:
            return False
        i = bisect.bisect_right(starts, x) - 1
        return i >= 0 and x <= nets[i][1]

    return is_tr


def from_big_lists() -> list[str]:
    try:
        is_tr = tr_ip_filter()
    except Exception as e:
        # без фильтра по стране проверять сотни тысяч адресов бессмысленно
        print(f"  [RIPE] не удалось получить диапазоны IP Турции, большие списки пропущены: {e}")
        return []

    def fetch(src):
        url, proto = src
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            return proto, r.text
        except Exception as e:
            print(f"  [{url.split('/')[3]}] не удалось: {e}")
            return proto, ""

    out, total = [], 0
    with ThreadPoolExecutor(max_workers=8) as ex:
        for proto, text in ex.map(fetch, BIG_LISTS):
            for m in PROXY_RE.finditer(text):
                total += 1
                if is_tr(m.group(2)):
                    scheme = (m.group(1) or proto).replace("https", "http")
                    out.append(f"{scheme}://{m.group(2)}:{m.group(3)}")
    print(f"  большие списки: {total} адресов, из них турецких {len(out)}")
    return out


def load_file(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [p for p in (normalize(l) for l in f) if p]


def collect_proxies(file: str | None, big: bool) -> list[str]:
    if file:
        proxies = load_file(file)
    else:
        print("Загружаю списки турецких прокси...")
        proxies = from_proxyscrape() + from_geonode() + from_proxifly() + from_spys()
        if big:
            print("Загружаю большие общие списки...")
            proxies += from_big_lists()
    seen, unique = set(), []
    for p in proxies:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def check_proxy(proxy: str, timeout: float) -> str | None:
    """Возвращает proxy, если он живой, реально турецкий и открывает PS Store."""
    # socks5h: DNS резолвится на стороне прокси — так же, как это делает Chromium
    rp = proxy.replace("socks5://", "socks5h://", 1)
    px = {"http": rp, "https": rp}
    try:
        r = requests.get(IP_CHECK_URL, proxies=px, timeout=timeout)
        if r.json().get("country") != "TR":
            return None
        # stream=True: ждём только заголовки ответа, а не всю страницу —
        # бесплатные прокси медленные, полная загрузка может занимать 20+ секунд
        with requests.get(
            STORE_URL,
            proxies=px,
            timeout=timeout * 3,
            headers={"User-Agent": "Mozilla/5.0"},
            stream=True,
        ) as r:
            if r.status_code == 200:
                return proxy
    except Exception:
        pass
    return None


def working_proxies(proxies: list[str], workers: int, timeout: float):
    """Генератор: отдаёт рабочие прокси по мере проверки."""
    ex = ThreadPoolExecutor(max_workers=workers)
    futures = [ex.submit(check_proxy, p, timeout) for p in proxies]
    checked = 0
    try:
        for fut in as_completed(futures):
            checked += 1
            res = fut.result()
            if checked % 25 == 0:
                print(f"  проверено {checked}/{len(proxies)}...")
            if res:
                yield res
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


def profile_busy(profile: Path) -> bool:
    """Профиль уже открыт другим окном Chromium (он держит lockfile открытым эксклюзивно)."""
    lock = profile / "lockfile"
    if not lock.exists():
        return False
    try:
        with open(lock, "a"):
            return False
    except PermissionError:
        return True


def has_login(profile: Path) -> bool:
    """Есть ли в профиле сохранённый вход в PSN (cookie единого входа Sony npsso)."""
    if not profile.exists():
        return False
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        context = pw.chromium.launch_persistent_context(str(profile), headless=True)
        try:
            return any(c["name"] == "npsso" for c in context.cookies())
        finally:
            context.close()


def login_browser(url: str, profile: Path) -> None:
    """Открывает страницу входа в Chromium, запущенном как обычная программа.

    Не через Playwright: защита Sony от ботов (Kasada/Akamai) распознаёт браузер
    под управлением автоматизации и блокирует запрос входа — на странице это
    выглядит как «Время соединения с сервером истекло». Профиль тот же, поэтому
    сохранённый здесь вход потом подхватит браузер с прокси.
    """
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        exe = pw.chromium.executable_path
    print("\nБраузер открыт без бесплатного прокси.")
    print("Войдите в аккаунт PSN, затем закройте окно браузера.")
    subprocess.run(
        [
            exe,
            f"--user-data-dir={profile}",
            "--lang=ru-RU",
            "--accept-lang=ru-RU,ru",
            "--no-first-run",
            "--no-default-browser-check",
            url,
        ]
    )


def open_browser(proxy: str, url: str, profile: Path) -> bool:
    """Открывает url в браузере с профилем profile через прокси proxy."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        # Постоянный профиль: cookies и вход в PSN сохраняются между запусками
        context = pw.chromium.launch_persistent_context(
            str(profile),
            headless=False,
            proxy={"server": proxy},
            locale="tr-TR",
            timezone_id="Europe/Istanbul",
            viewport=None,
            # скрывает navigator.webdriver (защиту Sony при входе этого не хватает,
            # поэтому вход идёт через login_browser)
            args=["--disable-blink-features=AutomationControlled"],
        )
        page = context.pages[0] if context.pages else context.new_page()
        try:
            page.goto(url, timeout=60_000, wait_until="domcontentloaded")
        except Exception as e:
            print(f"  браузер не смог открыть страницу через {proxy}: {e}")
            context.close()
            return False

        print(f"\nГотово: PS Store открыт через {proxy}")
        print(f"Профиль браузера: {profile}")
        print("Закройте окно браузера, чтобы завершить скрипт.")
        # Ждём через API Playwright: обычный time.sleep не обрабатывает события
        # sync-API, и закрытие окна никогда не было бы замечено
        try:
            while context.pages:
                context.pages[0].wait_for_event("close", timeout=0)
        except KeyboardInterrupt:
            pass
        except Exception:
            pass  # браузер закрыт целиком
        try:
            context.close()
        except Exception:
            pass
        return True


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="файл со своими прокси, по одному на строку")
    ap.add_argument("--workers", type=int, default=100, help="потоков проверки")
    ap.add_argument("--timeout", type=float, default=8, help="таймаут проверки, сек")
    ap.add_argument("--url", default=STORE_URL, help="адрес для открытия в браузере")
    ap.add_argument(
        "--profile",
        type=Path,
        default=DEFAULT_PROFILE,
        help="папка профиля браузера (cookies, вход в аккаунт)",
    )
    ap.add_argument(
        "--login",
        action="store_true",
        help="только открыть браузер без прокси для входа в PSN и выйти",
    )
    ap.add_argument(
        "--login-url", default=LOGIN_URL, help="страница, которая открывается для входа"
    )
    ap.add_argument(
        "--no-login",
        action="store_true",
        help="не предлагать вход, даже если его нет в профиле",
    )
    ap.add_argument(
        "--no-big", action="store_true", help="не загружать большие общие списки прокси"
    )
    args = ap.parse_args()

    if profile_busy(args.profile):
        print(f"Профиль браузера уже открыт в другом окне: {args.profile}")
        print("Закройте то окно браузера и запустите скрипт снова.")
        return 3

    if args.login or (not args.no_login and not has_login(args.profile)):
        if not args.login:
            print("Входа в PSN в профиле браузера нет.")
        login_browser(args.login_url, args.profile)
        if has_login(args.profile):
            print(f"Вход в PSN сохранён в профиле: {args.profile}")
        else:
            print("Вход в PSN не обнаружен — при следующем запуске окно входа откроется снова.")
        if args.login:
            return 0
        print()

    proxies = collect_proxies(args.file, big=not args.no_big)
    if not proxies:
        print("Список прокси пуст. Передайте свой через --file.")
        return 1
    print(f"Кандидатов: {len(proxies)}. Ищу рабочие...")

    for proxy in working_proxies(proxies, args.workers, args.timeout):
        print(f"Рабочий прокси: {proxy} — открываю браузер")
        if open_browser(proxy, args.url, args.profile):
            return 0
        print("Пробую следующий...")

    print("Рабочих турецких прокси не нашлось. Запустите позже или подставьте свой список.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
