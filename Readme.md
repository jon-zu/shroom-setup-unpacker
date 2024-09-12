# Shroom Setup Unpacker

A simple tool to unpack/extract the original setup executable without running It. For versions prior to v92 `cab` files are uses, this tool invokes `cabextract` for extraction, so for those older files ensure you have this on your pc.

# Example

This will extract the setup files into the default `setup` directory:
`cargo r --release -- -s setups/GMSSetupv95.exe`