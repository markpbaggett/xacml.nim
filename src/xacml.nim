import xmltools, strutils, strformat

type
  XACMLRule* = ref object of RootObj
    rule_id*: string
    effect*: string
    target_actions*: seq[string]
    excepted_roles*: seq[string]
    excepted_logins*: seq[string]
    body*: string

proc get_node(xml, node: string): seq[string] =
  let
    xml_response = Node.fromStringE(xml)
    new_data = $(xml_response // node)
  for part in new_data.split(fmt"<{node}"):
    if part != "":
      result.add(fmt"<{node}{part}")

proc build_actions(xml: string): seq[string]=
  let
    action_list = get_node(xml, "ActionMatch")
  for action in action_list:
    let
      attribute_values = get_node(action, "AttributeValue")
    for value in attribute_values:
      result.add(value.split('>')[1].split('<')[0])

proc get_attribute_value(xml, target_attribute: string): string =
  for value in xml.split(" "):
    if value.contains(target_attribute):
      return value.split("=")[1].replace("\"", "")

proc newXACMLRule(rule: string): XACMLRule =
  XACMLRule(
    body: rule,
    rule_id: get_attribute_value(rule, "RuleId"),
    effect: get_attribute_value(rule, "Effect").replace(">", "").replace("<Target", "").replace("\n", ""),
    target_actions: build_actions(rule)
  )

proc parse_rules*(response: string): seq[XACMLRule] =
  let
    xml_response = Node.fromStringE(response)
    rules = $(xml_response // "Rule")
  for rule in rules.split("<Rule"):
    if rule != "":
      result.add(newXACMLRule(fmt"<Rule{rule}"))

when isMainModule:
  let
    test_file = readFile("/home/mark/nim_projects/xacml/xml/restrict_management.xml")
    rules = parse_rules(test_file)
  for rule in rules:
    echo rule.target_actions
