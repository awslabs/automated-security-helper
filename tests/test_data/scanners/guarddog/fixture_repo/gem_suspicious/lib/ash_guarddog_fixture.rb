# Inert test fixture for the GuardDog scanner. Never loaded; the payload decodes
# to a puts call.
raise "inert test fixture"
require "base64"
eval(Base64.decode64("cHV0cyAnaW5lcnQgZ3VhcmRkb2cgZml4dHVyZSc="))
