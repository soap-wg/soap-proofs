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

fresh_reg = re.compile('!KU\( (~n\.?\d*) \)')
def gatherFreshNStream(lines):
  with_fresh = list(filter(bool, map(lambda ln: fresh_reg.match(ln[1]), lines)))
  return map(lambda match: match[1], with_fresh)

match = None
if argv[1] == 'TokenFormatAndOTPLearning':
  match = matchAgainstList([
    'ClaimUsername',
    'ClaimIdPKey',
    'GenCode',
    'GenNonce',
    '∃',
    '∀',
    '~~>',
    'St_OIDCServer_Auth',
    'St_OIDCIdP_Code',
    re.compile('SessionStore\(.+nonce'),
    '\'oidc_req\'',
    '\'login\'',
    '\'auth_req\'',
    '\'code\'',
    '\'token_req\'',
    '\'token\'',
    re.compile('tlsClientMsg.+<\'signal_req\', \$Number, ltk>'),
    'tlsClientMsg',  # lowest priority
  ], lines)
elif argv[1] in [
  'UsernamesUnique',
  'UsernamesServerConfirmed',
  'SignalKeysUnique',
]:
  match = matchAgainstList([
    '!SignalDomain',
    '!Domain',
    'St_',
    '!KU( ~IdPKey )',
    '\'oidc_req\'',
    'GenBrowserSession',
    '!KU( ~sess',
  ], lines)
elif argv[1] == 'PasswordsConfidential':
  match = matchAgainstList([
    '!Domain',
    'St_',
    '!KU( ~IdPKey )',
    '!KU( ~n )',
    '\'oidc_req\'',
    re.compile(r'GenBrowserSession\(.+,.+, ~(IdPKey|n)'),
    'GenBrowserSession',
  ], lines)
elif argv[1] == 'CodeVerifierSecrecy':
  match = matchAgainstList([
    '!Domain',
    '!KU( ~n )',
    '!KU( ~IdPKey )',
    re.compile(r'GenBrowserSession\(.+,.+, ~(IdPKey|n)'),
    '\'oidc_req\'',
  ], lines)
elif argv[1] == 'CodeIsSingleUse':
  match = matchAgainstList([
    re.compile(r'#\w\.?\d* < #\w\.?\d*'),
    'St_',
  ], lines)
elif argv[1] == 'SocialAuthentication':
  fvars = gatherFreshNStream(lines)
  rs = map(lambda fvar: re.compile(f'\(∀ #\w+\. \(!KU\( {re.escape(fvar)} \) @ #\w+\) ⇒ ⊥\)'), fvars)
  match = matchAgainstList(list(rs) + [
    'St_',
    '!Domain',
    re.compile(r'GenBrowserSession\(.+,.+, ~(IdPKey|sessPost|code|domain|signalApp)'),
    re.compile(r'tlsClientMsg\(~(IdPKey|sessPost|code|domain|signalApp)\.?\d*'),
    '!KU( ~IdPKey',
    '!KU( ~domain',
    '!KU( ~sessPost',
    '!KU( ~signalApp',
    '!KU( ~code',
    re.compile(r'\$\w+\.?\d* = \$\w+\.?\d*'),
    '\'code\'',
    '\'oidc_req\'',
    '~code',
    '\'token\'',
    '\'login\'',
    '\'auth_req\'',
    '!KU( ~sess',
    '\'sign_up\'',
    '\'idp_ack\'',
    '\'fwd_token\'',
    re.compile('∃ #\w+. \(Username(App|Server)\('),
    'GenBrowserSession',
    '!KU( sign',
    '~sessPost',
    '!KU( ~n',
  ], lines)
elif argv[1] == 'CodeVerifierSecrecy':
  match = matchAgainstList([
    '!Domain',
    '∃',
    '∀',
    '!KU( ~IdPKey )',
    re.compile(r'GenBrowserSession\(.+,.+,\s*~(IdPKey|n)'),
    re.compile(r'tlsClientMsg\(~(IdPKey|n),.+,\s*<\'oidc_req\''),
    '\'token_req\'',
    '!KU( ~n )',
  ], lines)
elif argv[1] == 'Executability':
  def defer(deferList, lines):
    for (num, goal) in lines:
      if matchesNone(deferList, (num, goal)):
        return num
    return matchAgainstList(deferList, lines)

  match = defer([
    re.compile('!KU\( tls'),
    re.compile('!KU\( browser'),
    re.compile('!KU\( [^~]'),
    re.compile('^!'),
    '∃',
    '∀',
    'GenBrowserSession(',
    'Browser(',
    'SessionStore(',
  ], lines)

if match is not None:
  print(match)
