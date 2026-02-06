import ssl
import socket
import datetime
import hashlib
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from colorama import init, Fore, Style

init(autoreset=True)


def get_certificate(host, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            return cert, ssock.version()


def analyze_certificate(cert, host):
    analysis = {}
    analysis["host"] = host
    analysis["subject"] = cert.subject.rfc4514_string()
    analysis["issuer"] = cert.issuer.rfc4514_string()
    analysis["serial_number"] = cert.serial_number
    analysis["version"] = cert.version.name
    analysis["not_valid_before"] = cert.not_valid_before
    analysis["not_valid_after"] = cert.not_valid_after
    analysis["signature_algorithm"] = cert.signature_algorithm_oid._name
    public_key = cert.public_key()
    analysis["key_type"] = type(public_key).__name__

    try:
        analysis["key_size"] = public_key.key_size
    except:
        analysis["key_size"] = None

    try:
        analysis["key_fingerprint_sha256"] = hashlib.sha256(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
    except:
        analysis["key_fingerprint_sha256"] = None

    analysis["subject_alt_names"] = []
    try:
        san = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        analysis["subject_alt_names"] = san.value.get_values_for_type(x509.DNSName)
    except:
        pass

    analysis["is_ca"] = False
    try:
        bc = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        analysis["is_ca"] = bc.value.ca
    except:
        pass

    analysis["key_usage"] = []
    try:
        ku = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        ).value
        if ku.digital_signature:
            analysis["key_usage"].append("Digital Signature")
        if ku.key_encipherment:
            analysis["key_usage"].append("Key Encipherment")
        if ku.key_agreement:
            analysis["key_usage"].append("Key Agreement")
        if ku.key_cert_sign:
            analysis["key_usage"].append("Certificate Sign")
        if ku.crl_sign:
            analysis["key_usage"].append("CRL Sign")
    except:
        pass

    analysis["extended_key_usage"] = []
    try:
        eku = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        )
        for usage in eku.value:
            analysis["extended_key_usage"].append(usage._name)
    except:
        pass

    now = datetime.datetime.utcnow()
    analysis["is_valid"] = analysis["not_valid_before"] <= now <= analysis["not_valid_after"]
    analysis["days_until_expiry"] = (analysis["not_valid_after"] - now).days
    analysis["self_signed"] = analysis["subject"] == analysis["issuer"]

    analysis["common_name"] = None
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            analysis["common_name"] = attr.value

    analysis["organization"] = None
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
            analysis["organization"] = attr.value

    analysis["country"] = None
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COUNTRY_NAME:
            analysis["country"] = attr.value

    return analysis


def check_certificate_issues(analysis):
    issues = []

    if not analysis["is_valid"]:
        issues.append(("CRITICAL", "Certificate is not valid"))

    if analysis["days_until_expiry"] < 0:
        issues.append(("CRITICAL", "Certificate expired"))
    elif analysis["days_until_expiry"] < 30:
        issues.append(("HIGH", "Certificate expiring soon"))

    if analysis["key_size"] and analysis["key_type"] == "RSAPublicKey":
        if analysis["key_size"] < 2048:
            issues.append(("HIGH", "Weak RSA key size"))

    if analysis["signature_algorithm"]:
        alg = analysis["signature_algorithm"].lower()
        if "sha1" in alg or "md5" in alg:
            issues.append(("HIGH", "Weak signature algorithm"))

    if analysis["self_signed"]:
        issues.append(("MEDIUM", "Self-signed certificate"))

    if analysis["common_name"]:
        if analysis["host"] not in analysis["subject_alt_names"]:
            issues.append(("MEDIUM", "Hostname mismatch"))

    if not analysis["subject_alt_names"]:
        issues.append(("LOW", "Missing SAN extension"))

    return issues


def run():
    target = input("Target (URL or hostname): ").strip()
    if not target:
        return

    if target.startswith("http"):
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443
    else:
        host = target
        port = 443

    try:
        cert, tls_version = get_certificate(host, port)
        analysis = analyze_certificate(cert, host)
        issues = check_certificate_issues(analysis)

        print("\nTLS:", tls_version)
        print("CN:", analysis["common_name"])
        print("Issuer:", analysis["issuer"])
        print("Valid until:", analysis["not_valid_after"])
        print("Days left:", analysis["days_until_expiry"])
        print("Key:", analysis["key_type"], analysis["key_size"])
        print("Signature:", analysis["signature_algorithm"])
        print("SAN:", ", ".join(analysis["subject_alt_names"]) or "None")

        if issues:
            print("\nIssues:")
            for sev, msg in issues:
                print(f"[{sev}] {msg}")
        else:
            print("\nNo security issues detected")

    except Exception as e:
        print("Error:", str(e))


if __name__ == "__main__":
    run()
