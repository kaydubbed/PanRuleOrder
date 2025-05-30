import xml.etree.ElementTree as ET
import csv
import argparse
import os
import sys

def read_policy_order_from_csv(csv_path):
    with open(csv_path, 'r') as file:
        reader = csv.reader(file)
        return [row[0].strip() for row in reader if row]

def find_rules_section(root, device_group, shared):
    ns = {'ns': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

    if shared:
        path = ".//ns:shared/ns:post-rulebase/ns:security/ns:rules" if ns else ".//shared/post-rulebase/security/rules"
        rules = root.find(path, ns)
        if rules is not None:
            return rules

        path = ".//ns:shared/ns:pre-rulebase/ns:security/ns:rules" if ns else ".//shared/pre-rulebase/security/rules"
        rules = root.find(path, ns)
        if rules is not None:
            return rules

        raise ValueError("❌ Shared security rules not found in pre- or post-rulebase.")

    entry_path = f".//ns:device-group/ns:entry[@name='{device_group}']" if ns else f".//device-group/entry[@name='{device_group}']"
    dg_entry = root.find(entry_path, ns)
    if dg_entry is None:
        raise ValueError(f"❌ Device group '{device_group}' not found.")

    post_path = "ns:post-rulebase/ns:security/ns:rules" if ns else "post-rulebase/security/rules"
    rules = dg_entry.find(post_path, ns)
    if rules is not None:
        print(f"ℹ️ Using post-rulebase rules for device group '{device_group}'")
        return rules

    pre_path = "ns:pre-rulebase/ns:security/ns:rules" if ns else "pre-rulebase/security/rules"
    rules = dg_entry.find(pre_path, ns)
    if rules is not None:
        print(f"ℹ️ Fallback: using pre-rulebase rules for device group '{device_group}'")
        return rules

    raise ValueError(f"❌ Security rules not found in pre- or post-rulebase for device group '{device_group}'.")

def reorder_policies(xml_path, csv_path, output_path, device_group, shared):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    rules_section = find_rules_section(root, device_group, shared)
    policy_map = {entry.attrib['name']: entry for entry in rules_section.findall("entry")}

    desired_order = read_policy_order_from_csv(csv_path)

    new_rules = []
    for name in desired_order:
        entry = policy_map.get(name)
        if entry is not None:
            new_rules.append(entry)
        else:
            print(f"⚠️ Warning: Policy '{name}' not found in the XML.")

    remaining = [entry for name, entry in policy_map.items() if name not in desired_order]
    if remaining:
        print("ℹ️ Note: The following policies were not in the CSV and will be added at the end:")
        for entry in remaining:
            print(f"    - {entry.attrib['name']}")
        new_rules.extend(remaining)

    rules_section.clear()
    for entry in new_rules:
        rules_section.append(entry)

    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    print(f"✅ Reordered XML written to: {output_path}")

def list_device_groups(root):
    print("📋 Available device groups in XML:")
    groups = root.findall(".//device-group/entry")
    if not groups:
        print("  (No device groups found)")
    for g in groups:
        print(f"  - {g.attrib.get('name')}")

def main():
    parser = argparse.ArgumentParser(description="Reorder Palo Alto Panorama security policies by CSV.")
    parser.add_argument("xml_file", help="Path to input Panorama XML.")
    parser.add_argument("csv_file", help="Path to CSV file with desired policy order.")
    parser.add_argument("output_file", help="Path to output reordered XML.")
    parser.add_argument("--device-group", help="Device group name to target.")
    parser.add_argument("--shared", action="store_true", help="Use shared policies instead of a device-group.")
    parser.add_argument("--list", action="store_true", help="List available device groups and exit.")

    args = parser.parse_args()

    if not os.path.exists(args.xml_file):
        print(f"❌ XML file not found: {args.xml_file}")
        sys.exit(1)

    if not args.list and not os.path.exists(args.csv_file):
        print(f"❌ CSV file not found: {args.csv_file}")
        sys.exit(1)

    tree = ET.parse(args.xml_file)
    root = tree.getroot()

    if args.list:
        list_device_groups(root)
        sys.exit(0)

    if not args.shared and not args.device_group:
        print("❌ You must specify a device group name with --device-group, or use --shared.")
        sys.exit(1)

    try:
        reorder_policies(
            xml_path=args.xml_file,
            csv_path=args.csv_file,
            output_path=args.output_file,
            device_group=args.device_group,
            shared=args.shared
        )
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
