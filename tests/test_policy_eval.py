"""Tests for ingestion/policy_eval.py (three-valued evaluation, Deny, trust, PassRole pairing)."""

from ingestion import policy_eval as pe

ACCT = "000000000000"
OIDC = f"arn:aws:iam::{ACCT}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"
K = "oidc.eks.us-east-1.amazonaws.com/id/ABC"


def _trust(cond=None, principal=None, action="sts:AssumeRoleWithWebIdentity"):
    st = {"Effect": "Allow", "Principal": principal or {"Federated": OIDC}, "Action": action}
    if cond:
        st["Condition"] = cond
    return {"Version": "2012-10-17", "Statement": [st]}


# ---- conditions ------------------------------------------------------------

def test_empty_condition_is_true():
    assert pe.evaluate_condition(None, {}) == pe.TRUE


def test_missing_key_is_unknown():
    assert pe.evaluate_condition({"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}, {}) == pe.UNKNOWN
    assert pe.evaluate_condition({"StringEquals": {"aws:RequestTag/x": "y"}}, {}) == pe.UNKNOWN


def test_bool_mfa_absent_is_false():
    c = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    assert pe.evaluate_condition(c, {"aws:multifactorauthpresent": pe.ABSENT}) == pe.FALSE


def test_negated_operator_with_absent_key_is_true():
    c = {"StringNotEquals": {"aws:username": "bob"}}
    assert pe.evaluate_condition(c, {"aws:username": pe.ABSENT}) == pe.TRUE


def test_ifexists_absent_is_true():
    c = {"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}}
    assert pe.evaluate_condition(c, {"aws:multifactorauthpresent": pe.ABSENT}) == pe.TRUE


def test_stringlike_glob():
    c = {"StringLike": {"iam:PassedToService": "ec2*"}}
    assert pe.evaluate_condition(c, {"iam:passedtoservice": "ec2.amazonaws.com"}) == pe.TRUE
    assert pe.evaluate_condition(c, {"iam:passedtoservice": "lambda.amazonaws.com"}) == pe.FALSE


def test_unsupported_operator_and_policy_variable_are_unknown():
    assert pe.evaluate_condition({"IpAddress": {"aws:SourceIp": "1.1.1.1"}},
                                 {"aws:sourceip": "1.1.1.1"}) == pe.UNKNOWN
    assert pe.evaluate_condition({"StringEquals": {"s3:prefix": "${aws:username}/*"}},
                                 {"s3:prefix": "bob/x"}) == pe.UNKNOWN
    assert pe.evaluate_condition({"ForAnyValue:StringEquals": {"a:b": "c"}}, {"a:b": "c"}) == pe.UNKNOWN


def test_and_across_keys_false_dominates_unknown():
    c = {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com", "aws:RequestTag/e": "prod"}}
    assert pe.evaluate_condition(c, {"iam:passedtoservice": "lambda.amazonaws.com"}) == pe.FALSE


# ---- Deny ------------------------------------------------------------------

def test_explicit_deny_beats_allow():
    stmts = [{"Effect": "Allow", "Action": "*", "Resource": "*"},
             {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}]
    assert pe.decide(stmts, "iam:PassRole", "arn:x") == "deny"
    assert pe.decide(stmts, "s3:GetObject", "arn:y") == "allow"


def test_conditional_deny_unknown_makes_allow_unresolved():
    stmts = [{"Effect": "Allow", "Action": "*", "Resource": "*"},
             {"Effect": "Deny", "Action": "*", "Resource": "*",
              "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}]
    assert pe.decide(stmts, "s3:GetObject", "arn:y") == "allow_unresolved"


def test_notaction_deny():
    stmts = [{"Effect": "Allow", "Action": "*", "Resource": "*"},
             {"Effect": "Deny", "NotAction": ["s3:*"], "Resource": "*"}]
    assert pe.decide(stmts, "s3:GetObject", "arn:y") == "allow"
    assert pe.decide(stmts, "iam:PassRole", "arn:y") == "deny"


def test_admin_status_inert_and_unresolved_and_partial():
    admin = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    base = {"is_admin": True}
    inert = {**base, "policy_documents": [{"Statement": [admin, {"Effect": "Deny", "Action": "*", "Resource": "*"}]}]}
    assert pe.admin_status(inert, pe.STRICT)["status"] == "inert"
    assert not pe.admin_status(inert, pe.STRICT)["is_admin"]
    unres = {**base, "policy_documents": [{"Statement": [admin, {"Effect": "Deny", "Action": "*", "Resource": "*",
              "Condition": {"IpAddress": {"aws:SourceIp": "1.1.1.1"}}}]}]}
    assert pe.admin_status(unres, pe.STRICT) == {"is_admin": True, "status": "unresolved", "partial_denies": []}
    part = {**base, "policy_documents": [{"Statement": [admin, {"Effect": "Deny", "Action": "s3:Delete*", "Resource": "*"}]}]}
    st = pe.admin_status(part, pe.STRICT)
    assert st["is_admin"] and st["status"] == "full_partial_deny"
    assert pe.admin_status(inert, pe.LEGACY)["is_admin"]      # legacy ignores Deny


# ---- IRSA trust --------------------------------------------------------------

def test_irsa_trust_valid_with_matching_sub_and_aud():
    doc = _trust({"StringEquals": {f"{K}:sub": "system:serviceaccount:default:app",
                                   f"{K}:aud": "sts.amazonaws.com"}})
    assert pe.irsa_trust_status(doc, "default", "app", pe.STRICT)[0] == "valid"


def test_irsa_trust_invalid_wrong_subject():
    doc = _trust({"StringEquals": {f"{K}:sub": "system:serviceaccount:kube-system:other"}})
    assert pe.irsa_trust_status(doc, "default", "app", pe.STRICT)[0] == "invalid"


def test_irsa_trust_stringlike_wildcard_subject():
    doc = _trust({"StringLike": {f"{K}:sub": "system:serviceaccount:default:*"}})
    assert pe.irsa_trust_status(doc, "default", "app", pe.STRICT)[0] == "valid"
    assert pe.irsa_trust_status(doc, "prod", "app", pe.STRICT)[0] == "invalid"


def test_irsa_trust_no_condition_is_valid_but_broad():
    assert pe.irsa_trust_status(_trust(), "default", "app", pe.STRICT)[0] == "valid"


def test_irsa_trust_ec2_service_trust_is_invalid():
    doc = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                          "Action": "sts:AssumeRole"}]}
    assert pe.irsa_trust_status(doc, "default", "app", pe.STRICT)[0] == "invalid"


def test_irsa_trust_mfa_condition_blocks():
    doc = _trust({"Bool": {"aws:MultiFactorAuthPresent": "true"}})
    assert pe.irsa_trust_status(doc, "default", "app", pe.STRICT)[0] == "invalid"


def test_irsa_trust_unknown_condition_is_unresolved():
    doc = _trust({"StringEquals": {"aws:RequestTag/team": "x"}})
    assert pe.irsa_trust_status(doc, "default", "app", pe.STRICT)[0] == "unresolved"


def test_irsa_trust_pinned_provider():
    other = f"arn:aws:iam::{ACCT}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/OTHER"
    cfg = pe.EvalConfig(oidc_provider_arn=other)
    assert pe.irsa_trust_status(_trust(), "default", "app", cfg)[0] == "invalid"


# ---- wildcard trust -----------------------------------------------------------

def test_wildcard_trust_unrestricted_and_conditioned():
    open_doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    cond_doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                               "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}}]}
    assert pe.wildcard_trust_status(open_doc) == "unrestricted"
    assert pe.wildcard_trust_status(cond_doc) == "conditioned"
    assert pe.wildcard_trust_status(_trust()) is None


# ---- PassRole pairing ----------------------------------------------------------

TARGET = f"arn:aws:iam::{ACCT}:role/target"
EC2_TRUST = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"}]}


def _pr(cond=None):
    s = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
    if cond:
        s["Condition"] = cond
    return s


def test_bare_passrole_is_potential():
    r = pe.passrole_analysis([_pr()], TARGET, EC2_TRUST, pe.STRICT)
    assert r["confidence"] == "potential"


def test_passrole_plus_runinstances_is_confirmed():
    stmts = [_pr(), {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}]
    r = pe.passrole_analysis(stmts, TARGET, EC2_TRUST, pe.STRICT)
    assert r["confidence"] == "confirmed" and r["services"] == ["ec2.amazonaws.com"]


def test_paired_action_for_wrong_service_does_not_confirm():
    stmts = [_pr(), {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}]
    assert pe.passrole_analysis(stmts, TARGET, EC2_TRUST, pe.STRICT)["confidence"] == "potential"


def test_passedtoservice_condition_restricts_services():
    stmts = [_pr({"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}),
             {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}]
    r = pe.passrole_analysis(stmts, TARGET, EC2_TRUST, pe.STRICT)   # target trusts only ec2
    assert r["confidence"] == "potential" and r["target_assumable_by_service"] is False


def test_passrole_deny_and_glob_resource():
    stmts = [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{ACCT}:role/app-*"}]
    assert pe.passrole_analysis(stmts, f"arn:aws:iam::{ACCT}:role/app-admin", EC2_TRUST, pe.STRICT)["decision"] == "allow"
    assert pe.passrole_analysis(stmts, TARGET, EC2_TRUST, pe.STRICT)["decision"] == "implicit_deny"
    stmts.append({"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"})
    assert pe.passrole_analysis(stmts, f"arn:aws:iam::{ACCT}:role/app-admin", EC2_TRUST, pe.STRICT)["decision"] == "deny"


def test_target_trust_mfa_blocks_service_assumption():
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}
    r = pe.passrole_analysis([_pr()], TARGET, trust, pe.STRICT)
    assert r["target_assumable_by_service"] is False
