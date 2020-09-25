# AutoCherry
Parses AutoRecon output files and imports them into Cherrytree.

- [AutoRecon](https://github.com/Tib3rius/AutoRecon)
- [Cherrytree](https://www.giuspen.com/cherrytree/)

AutoCherry will parse a given AutoRecon target directory and generate a Cherrytree notebook from it.  A node will be created for each open port, and subnodes will be created for extra files that AutoRecon generates for that port. AutoRecon is primarily meant as a tool for CTFs, so the template is built for them too.

![alt text](https://github.com/burntfuzz/autocherry/blob/master/examples/blunder_example.png "HTB: Blunder")

![alt text](https://github.com/burntfuzz/autocherry/blob/master/examples/friendzone_example.png "HTB: Friendzone")

AutoCherry only generates notebooks for single targets. You can use the `--single-target` flag in AutoRecon to scan a single host and create a single target directory instead of a `/results` directory. A valid AutoRecon target directory should contain a `/scans` subdirectory which contains scan results and an `/xml` subdirectory:

```
autorecon_target_dir/
├── exploit/
├── loot/
├── report/
│   ├── local.txt
│   ├── notes.txt
│   ├── proof.txt
│   └── screenshots/
└── scans/
    ├── _commands.log
    ├── _manual_commands.txt
    └── xml/
```
You can also generate an empty template with the `-e` flag, or you can just grab one from the `/examples` directory.

This is designed to work with AutoRecon's default configuration, so it may not behave as expected with custom scan profiles. It should still work fine as long as the output filenames in your custom scan profile are the same as the default configuration's.

This will output a `.ctd` file for use with Cherrytree. You can convert to another format by opening it in Cherrytree then clicking on `File` > `Save As` and selecting your desired file type.

## Requirements

 - Python 3.6+
 - `python3-libnmap`

## Usage

```
usage: autocherry.py [-h] (-d DIR | -e) [-o OUTPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -d DIR                AutoRecon target directory to parse
  -e                    Do not parse an AutoRecon target directory and create an empty template
  -o OUTPUT_FILE, --output OUTPUT_FILE

usage examples:
  python3 autocherry.py -d autorecon_target_dir -o AutoReconNotes
  python3 autocherry.py -e -o EmptyTemplate
```
