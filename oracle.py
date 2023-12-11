#!/usr/bin/env python3

from sys import argv, stdin, exit
import re

# This oracle helps tamarin with a sources for OpenID Connect tokens. These
# tokens contain a hash (non-invertible). Tamarin thinks it can derive anything
# from these. This oracle ranks proof goals determining the origin of these
# hashes higher (see regex).

def splitter(line):
  splitted = line.split(':')
  return (splitted[0], splitted[1].strip())

lines = list(map(splitter, stdin.readlines()))
if not lines:
  exit(0)

def subToken(token, line):
  (num, goal) = line
  if isinstance(token, str):
    return num if token in goal else None
  else:
    return num if token.search(goal) is not None else None

def matchesNone(tokens, line):
  for token in tokens:
    if subToken(token, line):
      return False
  return True

def matchAgainstList(priorityList, lines):
  for token in priorityList:
    try:
      return next(filter(bool, map(lambda line: subToken(token, line), lines)))
    except StopIteration:
      pass

nonSessionGoals = [
    'TLSServer_In( \'GET\', ~sessPost',
    'TLSClient_In( \'GET\', ~sessPost',
    re.compile(r'TLS(Server|Client)_In\( \'\w+\', ~(pw|idpSk|code|domain|signalApp|sk|adversarySess|challenge)'),
]

match = None
if argv[1] == 'TokenFormatAndOTPLearning':
  match = matchAgainstList([
    'MustBe',
    '\'oidc_req\'',
    '\'token\'',
    '\'code\'',
    'St_OIDCServer_Auth',
    'St_OIDCIdP_Code',
    'St_OIDCApp_CodeReq',
    '!MessagingLtkServer',
    'St_SigReg_Server',
    'GenCode',
    'GenNonce',
    '∃',
    '∀',
    '~~>',
    re.compile(r'SessionStore\(.+nonce'),
    '\'login\'',
    '\'auth_req\'',
    '\'token_req\'',
    re.compile(r'TLSServer_In.+<\'signal_req\', \$Number, ltk>'),
    'TLSServer_In',
  ], lines)
elif argv[1] == 'PasswordsConfidential':
  match = matchAgainstList([
    '!Domain',
    'St_',
    '!KU( ~idpSk )',
    '!KU( ~n )',
    '\'oidc_req\'',
  ], lines)
elif argv[1] == 'CodeSecrecy':
  match = matchAgainstList(nonSessionGoals + [
    re.compile(r'TLSServer_In\( \'GET\', ~sess(\.\d+)?, \$RedirectURL(\.\d+)?, <\'code\''),
    'St_OIDCIdP_Code(',
    '!KU( ~code )',
    '\'token_req\'',
  ], lines)
elif argv[1] == 'CodeVerifierSecrecy':
  match = matchAgainstList([
    '!Domain',
    '!KU( ~n )',
    '!KU( ~idpSk )',
    '\'oidc_req\'',
  ], lines)
elif argv[1] == 'CodeAgreement':
  match = matchAgainstList(nonSessionGoals + [
    'last',
    '!KU( ~sessPost',
    'codeClient = ~code',
    'St_OIDCApp_CodeReq',
    '\'POST\'',
  ], lines)
elif argv[1] == 'CodeIsSingleUse':
  match = matchAgainstList(nonSessionGoals + [
    'last',
    re.compile(r'~?code(\.\d+)? = ~code(\.\d+)?'),
    re.compile(r'TLSServer_In\( \'GET\', ~sess(\.\d+)?, \$RedirectURL(\.\d+)?, <\'code\''),
    '\'POST\'',
    'St_OIDCApp_CodeReq',
  ], lines)
elif argv[1] == 'SocialAuthentication':
  match = matchAgainstList(nonSessionGoals + [
    '∃',
    '!MessagingLtkUser',
    '!UseMessagingKeyFor',
    '!IdPAccount',
    '!Publish',
    re.compile(r'E2EE_In\(.+, .+, m1 \)'),
    '!KU( ~sk',
  ], lines)
elif argv[1] == 'CodeVerifierSecrecy':
  match = matchAgainstList([
    '!Domain',
    '∃',
    '∀',
    '!KU( ~idpSk )',
    re.compile(r'GenBrowserSession\(.+,.+,\s*~(idpSk|n)'),
    re.compile(r'TLSServer_In\(~(idpSk|n),.+,\s*<\'oidc_req\''),
    '\'token_req\'',
    '!KU( ~n )',
  ], lines)
elif argv[1] == 'Executability':
  def defer(deferList, lines):
    for (num, goal) in lines:
      if matchesNone(deferList, (num, goal)):
        return num
    return matchAgainstList(deferList, lines)
  match = matchAgainstList(['!KU( ~'], lines)
  if match is None:
    match = defer(['SessionStore'], lines)
elif argv[1] == 'SOAPAgreement':
  match = matchAgainstList(nonSessionGoals + [
    '!MessagingApp',
    '!KU( ~sk',
    '∃',
    '∀',
    'St_OIDC',
    re.compile(r'TLSServer_In\( \'GET\', ~sess(\.\d+)?, \$RedirectURL(\.\d+)?, <\'code\''),
    '\'POST\'',
    '!KU( ~idpSk',
    '!KU( ~domain',
    '!KU( ~sessPost',
    '!KU( ~signalApp',
    '!KU( ~code',
    '\'fwd_token\'',
    '\'code\'',
    '\'oidc_req\'',
    '\'token\'',
    '\'login\'',
    '!KU( sign',
    '!KU( ~adversarySess',
  ], lines)
elif argv[1] == 'IdPChannelSenderInvarianceAgreement':
  match = matchAgainstList(nonSessionGoals + [
    '!KU( ~pw',
  ], lines)
elif argv[1] == 'MessagingSenderInvarianceAgreement':
  match = matchAgainstList(nonSessionGoals + [
    '!KU( ~sk',
    '!KU( ~challenge',
    '!MessagingLtkUser',
    '!UseMessagingKeyFor',
    'E2EE_In',
    'St_SigReg_Server',
    '\'otp_respond\'',
  ], lines)

if match is not None:
  print(match)
