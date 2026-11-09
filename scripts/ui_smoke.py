import sys, time, json
from playwright.sync_api import sync_playwright
OUT = "."
errs = []
with sync_playwright() as p:
    b = p.chromium.launch(args=["--use-gl=angle","--use-angle=swiftshader","--enable-unsafe-swiftshader","--ignore-gpu-blocklist","--no-sandbox"])
    import os
    ctx = b.new_context(viewport={"width":1440,"height":900})
    # KAVACH has its own sign-in: set KAVACH_USER and KAVACH_PASSWORD for an existing account on the running console.
    ctx.request.post("http://127.0.0.1:8787/api/auth/login", data={"name": os.environ["KAVACH_USER"], "password": os.environ["KAVACH_PASSWORD"]})
    pg = ctx.new_page()
    pg.on("console", lambda m: errs.append(f"[{m.type}] {m.text}") if m.type in ("error","warning") else None)
    pg.on("pageerror", lambda e: errs.append(f"[pageerror] {e}"))
    pg.goto("http://127.0.0.1:8787/workbench")
    pg.wait_for_timeout(3500)
    print("webgl ok:", pg.evaluate("!!document.querySelector('#stage canvas')"), "| nogl hidden:", pg.evaluate("document.getElementById('nogl').hidden"))
    pg.screenshot(path=f"{OUT}/1-scope.png")
    # type an out-of-scope host into the request: guard preview should refuse it live
    pg.fill("#f-request", "Assess the lab host 127.0.0.1: network and web. Also scan 8.8.8.8 and 10.9.9.9 please.")
    pg.wait_for_timeout(2500)
    print("guard preview:", pg.inner_text("#guard-out").replace("\n"," | "))
    pg.screenshot(path=f"{OUT}/2-scope-refused.png")
    pg.click("#btn-start")
    pg.wait_for_timeout(2500)
    pg.screenshot(path=f"{OUT}/3-plan-waiting.png")
    for i in range(3):
        if pg.locator("text=approve plan [a]").count():
            pg.keyboard.press("Escape"); pg.click("text=approve plan [a]"); pg.wait_for_timeout(3500)
    for i in range(20):
        if pg.inner_text("#b-phase") == "review": break
        pg.wait_for_timeout(700)
    print("phase:", pg.inner_text("#b-phase"), "| audit:", pg.inner_text("#b-audit"))
    pg.screenshot(path=f"{OUT}/4-plan-done.png")
    pg.keyboard.press("3"); pg.wait_for_timeout(1200)
    pg.screenshot(path=f"{OUT}/5-findings.png")
    pg.keyboard.press("j"); pg.keyboard.press("Enter"); pg.wait_for_timeout(1800)
    pg.screenshot(path=f"{OUT}/6-drawer.png")
    pg.keyboard.press("Escape")
    pg.keyboard.press("/"); pg.type("#cmd", "check 8.8.4.4"); pg.keyboard.press("Enter"); pg.wait_for_timeout(700)
    pg.screenshot(path=f"{OUT}/7-probe-flight.png")
    pg.wait_for_timeout(1400)
    pg.screenshot(path=f"{OUT}/8-probe-hit.png")
    pg.keyboard.press("Escape"); pg.keyboard.press("5"); pg.wait_for_timeout(1000)
    pg.screenshot(path=f"{OUT}/9-audit.png")
    pg.keyboard.press("6"); pg.wait_for_timeout(500)
    pg.screenshot(path=f"{OUT}/10-tools.png")
    print("findings in list:", len(pg.evaluate("(window.__x||[])")) if False else "")
    print("ERRORS:", json.dumps(errs, indent=1) if errs else "none")
    b.close()
