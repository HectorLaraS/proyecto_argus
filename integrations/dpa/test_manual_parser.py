from pprint import pprint

from integrations.dpa.parser import parse_dpa_trap, build_dpa_issue


def main():
    trap = {
        "timestamp": "2026-03-05 18:10:33",
        "src_ip": "10.1.59.226",
        "community": "dpa_test",
        "oids": [
            {"oid": "1.3.6.1.4.1.22980.1.1", "value": r"KCTACTOOLSD03\SQLEXPRESS"},
            {"oid": "1.3.6.1.4.1.22980.1.2", "value": "TAC TEST dpa_test Service Null"},
            {"oid": "1.3.6.1.4.1.22980.1.3", "value": "HIGH"},
            {"oid": "1.3.6.1.4.1.22980.1.5", "value": "Thursday - March 05, 2026 18:00:33"},
            {"oid": "1.3.6.1.4.1.22980.1.8", "value": "6"},
        ],
    }

    parsed = parse_dpa_trap(trap)
    issue = build_dpa_issue(parsed)

    print("=== DpaTrapParsed ===")
    pprint(parsed)

    print("\n=== DpaIssue ===")
    pprint(issue)


if __name__ == "__main__":
    main()