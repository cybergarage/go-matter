## matterctl



### Options

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
  -h, --help            help for matterctl
      --verbose         enable verbose output
```

* [matterctl doc]()	 - Generate markdown documentation to stdout
* [matterctl pairing]()	 - Pairing Matter devices.
* [matterctl scan]()	 - Scan for Matter devices.

## matterctl completion

Generate the autocompletion script for the specified shell

### Synopsis

Generate the autocompletion script for matterctl for the specified shell.
See each sub-command's help for details on how to use the generated script.


### Options

```
  -h, --help   help for completion
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```

* [matterctl completion bash]()	 - Generate the autocompletion script for bash
* [matterctl completion fish]()	 - Generate the autocompletion script for fish
* [matterctl completion powershell]()	 - Generate the autocompletion script for powershell
* [matterctl completion zsh]()	 - Generate the autocompletion script for zsh

## matterctl completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(matterctl completion bash)

To load completions for every new session, execute once:

#### Linux:

	matterctl completion bash > /etc/bash_completion.d/matterctl

#### macOS:

	matterctl completion bash > $(brew --prefix)/etc/bash_completion.d/matterctl

You will need to start a new shell for this setup to take effect.


```
matterctl completion bash
```

### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	matterctl completion fish | source

To load completions for every new session, execute once:

	matterctl completion fish > ~/.config/fish/completions/matterctl.fish

You will need to start a new shell for this setup to take effect.


```
matterctl completion fish [flags]
```

### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl completion help

Help about any command

### Synopsis

Help provides help for any command in the application.
Simply type completion help [path to command] for full details.

```
matterctl completion help [command] [flags]
```

### Options

```
  -h, --help   help for help
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl completion powershell

Generate the autocompletion script for powershell

### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	matterctl completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
matterctl completion powershell [flags]
```

### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(matterctl completion zsh)

To load completions for every new session, execute once:

#### Linux:

	matterctl completion zsh > "${fpath[1]}/_matterctl"

#### macOS:

	matterctl completion zsh > $(brew --prefix)/share/zsh/site-functions/_matterctl

You will need to start a new shell for this setup to take effect.


```
matterctl completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl doc

Generate markdown documentation to stdout

```
matterctl doc [flags]
```

### Options

```
  -h, --help   help for doc
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl help

Help about any command

### Synopsis

Help provides help for any command in the application.
Simply type matterctl help [path to command] for full details.

```
matterctl help [command] [flags]
```

### Options

```
  -h, --help   help for help
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl pairing

Pairing Matter devices.

### Synopsis

Pairing Matter devices by specifying node ID and pairing code.

### Options

```
  -h, --help   help for pairing
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```

* [matterctl pairing code]()	 - Pair using node ID and pairing code.
* [matterctl pairing code-wifi]()	 - Pair using node ID, pairing code, and WiFi credentials.

## matterctl pairing code

Pair using node ID and pairing code.

```
matterctl pairing code <node ID> <pairing code> [flags]
```

### Options

```
  -h, --help   help for code
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl pairing code-wifi

Pair using node ID, pairing code, and WiFi credentials.

```
matterctl pairing code-wifi <node ID> <pairing code> <WIFI SSID> <WIFI password> [flags]
```

### Options

```
  -h, --help   help for code-wifi
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl pairing help

Help about any command

### Synopsis

Help provides help for any command in the application.
Simply type pairing help [path to command] for full details.

```
matterctl pairing help [command] [flags]
```

### Options

```
  -h, --help   help for help
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


## matterctl scan

Scan for Matter devices.

### Synopsis

Scan for Matter devices. Optionally filter devices using a manual pairing code.

```
matterctl scan [pairing code] [flags]
```

### Options

```
  -h, --help   help for scan
```

### Options inherited from parent commands

```
      --debug           enable debug output
      --format string   output format: table|json|csv (default "table")
      --verbose         enable verbose output
```


