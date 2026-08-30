#!/bin/bash
# Benchmark 11 -- adversarial / evasion stress tests.
set -e
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

mkrole() { awslocal iam create-role --role-name "$1" --assume-role-policy-document "$2" >/dev/null; }
putpol() { awslocal iam put-role-policy --role-name "$1" --policy-name "$2" --policy-document "$3" >/dev/null; }

# 1. Wildcard trust Principal ("AWS": "*") with NO narrowing condition --
# a genuinely severe real vulnerability (anyone can assume this role).
# Expect: TP.
mkrole b11-wildcard-principal-admin '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
awslocal iam attach-role-policy --role-name b11-wildcard-principal-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2. Deeply nested/combined Conditions on the PERMISSION policy (not trust) --
# tests ingestion doesn't break on complex condition blocks. Trust is simple
# (EC2 service), so IRSA reachability is unaffected; should still be TP
# since the escalation-relevant edge (iam:PassRole) itself isn't gated by
# these conditions in a way that blocks IRSA-originated principals.
mkrole b11-nested-conditions-target '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam attach-role-policy --role-name b11-nested-conditions-target --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
mkrole b11-nested-conditions '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
putpol b11-nested-conditions nested-cond-passrole '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b11-nested-conditions-target","Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"},"StringLike":{"aws:RequestTag/Environment":"prod*"},"Bool":{"aws:SecureTransport":"true"}}}]}'

# 3. Obfuscated 5-hop chain: bridge -> r1 -PassRole-> r2 -AssumeRole-> r3 -PassRole-> r4 -AssumeRole-> admin
mkrole b11-hop4-admin '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b11-hop3"},"Action":"sts:AssumeRole"}]}'
awslocal iam attach-role-policy --role-name b11-hop4-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
mkrole b11-hop3 '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
putpol b11-hop3 passrole-to-hop4 '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b11-hop4-admin"}]}'
mkrole b11-hop2 '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
putpol b11-hop2 assume-hop3 '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/b11-hop3"}]}'
awslocal iam update-assume-role-policy --role-name b11-hop3 --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b11-hop2"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
mkrole b11-hop1 '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
putpol b11-hop1 passrole-to-hop2 '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b11-hop2"}]}'

# 4. Circular trust pair, NEITHER is admin -- must not crash / infinite-loop,
# and must correctly report 0 paths (safe cycle).
mkrole b11-circular-a '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b11-circular-b"},"Action":"sts:AssumeRole"}]}'
mkrole b11-circular-b '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b11-circular-a"},"Action":"sts:AssumeRole"}]}'
putpol b11-circular-a s3-perms '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'

echo "Benchmark 11 AWS setup complete: 4 adversarial/evasion cases."
