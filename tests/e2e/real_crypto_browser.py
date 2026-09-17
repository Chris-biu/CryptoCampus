"""Fresh desktop Chromium context, no network interception or crypto substitutes."""

import argparse
import json
import os
from pathlib import Path
import xml.etree.ElementTree as ET

from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--discover", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel="chrome")
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        guest = browser.new_context(viewport={"width": 1440, "height": 1000})
        passed = []
        page_errors = []
        try:
            page = context.new_page()
            page.on("pageerror", lambda error: page_errors.append(type(error).__name__))
            page.goto(args.base_url + "/login")
            page.wait_for_load_state("networkidle")
            if args.discover:
                print(
                    json.dumps(
                        {
                            "login_inputs": page.locator("input").evaluate_all(
                                "els => els.map(e => ({type:e.type,testid:e.dataset.testid,placeholder:e.placeholder}))"
                            )
                        }
                    )
                )
            page.get_by_test_id("login-email").fill("desktop@campus.edu")
            page.get_by_test_id("login-password").fill(
                os.environ["CC_REAL_E2E_PASSWORD"]
            )
            page.get_by_test_id("login-submit").click()
            expect(page.get_by_role("heading", name="服务大厅")).to_be_visible()
            passed.append("real_login_to_desktop_hall")
            page.goto(args.base_url + "/drop/create")
            page.wait_for_load_state("networkidle")
            if args.discover:
                print(
                    json.dumps(
                        {
                            "drop_controls": page.locator(
                                "input,textarea,button"
                            ).evaluate_all(
                                "els => els.map(e => ({type:e.type,testid:e.dataset.testid,text:e.textContent,placeholder:e.placeholder}))"
                            )
                        }
                    )
                )
                page.screenshot(
                    path=str(args.output / "drop-ready.png"), full_page=True
                )
            else:
                content = "Desktop real SM2 and SM4-GCM roundtrip"
                page.get_by_test_id("drop-content").fill(content)
                page.get_by_test_id("drop-password").fill("Disposable9!Access")
                with page.expect_response(
                    lambda response: response.url.endswith("/api/v1/drops/text")
                ) as event:
                    page.get_by_test_id("create-drop").click()
                assert event.value.status == 201, "real drop creation failed"
                link = event.value.json()
                expect(page.get_by_test_id("result-code")).to_have_text(
                    link["access_code"]
                )
                reader = guest.new_page()
                reader.on(
                    "pageerror", lambda error: page_errors.append(type(error).__name__)
                )
                reader.goto(args.base_url + "/d/" + link["code"])
                reader.wait_for_load_state("networkidle")
                reader.get_by_label("提取码", exact=True).fill(link["access_code"])
                reader.get_by_label("附加提取口令", exact=True).fill(
                    "Disposable9!Access"
                )
                with reader.expect_response(
                    lambda response: response.url.endswith("/extract")
                ) as extraction:
                    reader.get_by_test_id("extract-submit").click()
                assert extraction.value.status == 200, "real public extraction failed"
                expect(
                    reader.get_by_role("heading", name="身份校验通过")
                ).to_be_visible()
                expect(reader.locator("body")).to_contain_text(content)
                expect(reader.get_by_text("已经提取", exact=True)).to_be_visible()
                expect(reader.get_by_test_id("extract-submit")).to_be_disabled()
                reader.screenshot(
                    path=str(args.output / "drop-extracted.png"), full_page=True
                )
                reader.reload()
                reader.wait_for_load_state("networkidle")
                expect(reader.locator("body")).not_to_contain_text(content)
                passed.append("real_drop_create_public_extract_and_burn")
            page.goto(args.base_url + "/verify")
            page.wait_for_load_state("networkidle")
            if args.discover:
                print(
                    json.dumps(
                        {
                            "verify_controls": page.locator(
                                "input,button"
                            ).evaluate_all(
                                "els => els.map(e => ({type:e.type,text:e.textContent,placeholder:e.placeholder}))"
                            )
                        }
                    )
                )
                page.screenshot(
                    path=str(args.output / "verify-ready.png"), full_page=True
                )
                return
            document = b"%PDF-1.4\n% Disposable browser regression\n%%EOF\n"
            page.get_by_role("button", name="签发凭证").click()
            page.locator('input[type="file"]').nth(0).set_input_files(
                {
                    "name": "proof.pdf",
                    "mimeType": "application/pdf",
                    "buffer": document,
                },
            )
            with page.expect_response(
                lambda response: response.url.endswith("/api/v1/seals")
            ) as seal:
                page.get_by_role("button", name="盖章并生成凭证").click()
            assert seal.value.status == 201, "real personal seal creation failed"
            expect(page.get_by_text("签发完成", exact=True)).to_be_visible()
            with page.expect_download() as download:
                page.get_by_role("button", name="下载 Sidecar 验真凭证").click()
            sidecar_path = download.value.path()
            page.get_by_role("button", name="验证文件", exact=True).click()
            page.locator('input[type="file"]').nth(1).set_input_files(sidecar_path)
            with page.expect_response(
                lambda response: response.url.endswith("/api/v1/verifications")
            ) as verification:
                page.get_by_role("button", name="开始五步验真").click()
            assert (
                verification.value.status == 200 and verification.value.json()["valid"]
            )
            expect(page.get_by_text("五项检查全部通过", exact=True)).to_be_visible()
            expect(page.get_by_text("签章时间", exact=True)).to_be_visible()
            expect(page.locator("body")).not_to_contain_text("可信时间戳")
            page.screenshot(path=str(args.output / "seal-verified.png"), full_page=True)
            passed.append("real_personal_seal_download_and_five_step_verification")
            page.locator('input[type="file"]').nth(0).set_input_files(
                {
                    "name": "proof.pdf",
                    "mimeType": "application/pdf",
                    "buffer": document + b"changed",
                },
            )
            with page.expect_response(
                lambda response: response.url.endswith("/api/v1/verifications")
            ) as tampered:
                page.get_by_role("button", name="开始五步验真").click()
            assert tampered.value.status == 200 and not tampered.value.json()["valid"]
            expect(page.get_by_text("验真未通过", exact=True)).to_be_visible()
            page.screenshot(path=str(args.output / "seal-tampered.png"), full_page=True)
            passed.append("tampered_file_is_rejected_in_desktop_ui")
            page.get_by_test_id("logout").click()
            expect(page.get_by_test_id("login-submit")).to_be_visible()
            assert page.evaluate(
                "localStorage.length === 0 && sessionStorage.length === 0"
            )
            assert not page_errors, "browser reported application errors"
            passed.append("logout_and_no_browser_storage_residue")
            print(
                json.dumps(
                    {
                        "passed": len(passed),
                        "cases": passed,
                        "page_errors": len(page_errors),
                    }
                )
            )
        finally:
            if not args.discover:
                suite = ET.Element(
                    "testsuite",
                    name="real-desktop-crypto",
                    tests=str(len(passed) + (len(passed) != 5)),
                    failures=str(0 if len(passed) == 5 else 1),
                )
                for name in passed:
                    ET.SubElement(suite, "testcase", name=name)
                if len(passed) != 5:
                    case = ET.SubElement(
                        suite, "testcase", name="remaining_desktop_flow"
                    )
                    ET.SubElement(
                        case,
                        "failure",
                        message="Desktop flow did not complete; see console",
                    )
                ET.ElementTree(suite).write(
                    args.output / "junit.xml", encoding="utf-8", xml_declaration=True
                )
            guest.close()
            context.close()
            browser.close()


if __name__ == "__main__":
    main()
