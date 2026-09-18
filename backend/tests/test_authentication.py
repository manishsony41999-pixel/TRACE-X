"""
Unit tests for SPF, DKIM, and DMARC Authentication Engine
"""

from app.services.authentication import analyze_authentication, query_dns_txt


def test_analyze_authentication_from_headers():
    auth_headers = [
        "mx.google.com; spf=pass (google.com: domain of support@legit.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=support@legit.com; dkim=pass header.i=@legit.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=legit.com"
    ]
    dkim_signatures = ["v=1; a=rsa-sha256; c=relaxed/relaxed; d=legit.com; s=google; ..."]

    res = analyze_authentication(
        sender_domain="legit.com",
        auth_headers=auth_headers,
        dkim_signatures=dkim_signatures
    )

    assert res["spf"]["status"] == "pass"
    assert res["dkim"]["status"] == "pass"
    assert res["dmarc"]["status"] == "pass"
    assert res["dkim"]["is_signed"] is True


def test_analyze_authentication_failures():
    auth_headers = [
        "mx.google.com; spf=fail (google.com: domain of evil.com does not designate 198.51.100.1 as permitted sender); dkim=fail; dmarc=fail"
    ]
    res = analyze_authentication(
        sender_domain="evil.com",
        auth_headers=auth_headers,
        dkim_signatures=[]
    )

    assert res["spf"]["status"] == "fail"
    assert res["dkim"]["status"] == "fail"
    assert res["dmarc"]["status"] == "fail"
    assert res["dkim"]["is_signed"] is False
