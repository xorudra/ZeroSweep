# apktool (Prompt 17 §18)

Resource and manifest decoding in the safe extraction workspace.
Output (decoded `AndroidManifest.xml`, resources, smali inventory)
feeds manifest analysis: permissions, exported components, deep
links, network security config. Archive attacks are refused at
intake before apktool ever sees the file (§107).
