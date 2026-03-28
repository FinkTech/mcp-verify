# VHS Demo Scripts

VHS (Video Home System) scripts for generating animated GIFs/MP4s showcasing mcp-verify features.

## Prerequisites

Install VHS:
```bash
# Ubuntu/Debian
sudo apt install ffmpeg
go install github.com/charmbracelet/vhs@latest
# Make sure $GOPATH/bin is in your PATH

# macOS
brew install vhs

# Windows (via scoop)
scoop install vhs
```

## Before Recording

1. **Build the project**:
   ```bash
   cd mcp-verify
   npm run build
   ```

2. **Clean previous reports**:
   ```bash
   rm -rf reports/
   mkdir -p reports
   ```

## Generate Demos

```bash
# From project root
cd demo-vhs

# Generate individual demos
vhs 01-quickstart.tape
vhs 02-interactive-shell.tape
vhs 03-schema-aware-fuzzing.tape
vhs 04-security-gateway.tape
vhs 05-doctor-diagnostics.tape
vhs 06-reports-formats.tape

# Or generate all at once
for tape in *.tape; do vhs "$tape"; done
```

**Output**: GIFs will be in `demo-vhs/*.gif`

## Demos Overview

| Demo | Description | Output |
|------|-------------|--------|
| `01-quickstart.tape` | Basic validation with HTML report | `demo-vhs/01-quickstart.gif` |
| `02-interactive-shell.tape` | Multi-context workspace, profiles, persistence | `demo-vhs/02-interactive-shell.gif` |
| `03-schema-aware-fuzzing.tape` | Advanced fuzzing with schema parsing | `demo-vhs/03-schema-aware-fuzzing.gif` |
| `04-security-gateway.tape` | Real-time threat detection proxy | `demo-vhs/04-security-gateway.gif` |
| `05-doctor-diagnostics.tape` | Environment checks and troubleshooting | `demo-vhs/05-doctor-diagnostics.gif` |
| `06-reports-formats.tape` | Multiple report formats (HTML, JSON, SARIF, MD) | `demo-vhs/06-reports-formats.gif` |

## Customization

Edit `.tape` files to adjust:
- `Set Width` / `Set Height` - Terminal dimensions (default: 1200x700)
- `Set TypingSpeed` - Speed of typing (default: 50ms)
- `Set PlaybackSpeed` - Playback multiplier (default: 1.0)
- `Sleep` durations - Pause between commands
- `Set Theme` - Color scheme (current: "Dracula")

Available themes: Dracula, Monokai, Nord, Catppuccin Mocha, etc.

## Tips

1. **Test command first**: Run commands manually before recording
2. **Adjust timing**: If commands take longer, increase `Sleep` durations
3. **Convert to MP4**: Change `Output` line to `.mp4` extension
   ```tape
   Output demo-vhs/01-quickstart.mp4
   ```
4. **Reduce GIF size**: Use `gifsicle` to compress
   ```bash
   sudo apt install gifsicle
   gifsicle -O3 --lossy=80 -o compressed.gif original.gif
   ```

## Troubleshooting

**Issue**: `bash: vhs: command not found`
- Solution: Add `$GOPATH/bin` to PATH:
  ```bash
  export PATH="$PATH:$(go env GOPATH)/bin"
  ```

**Issue**: Commands run too fast/slow
- Solution: Adjust `Sleep` durations in `.tape` files

**Issue**: Terminal looks different
- Solution: Change `Set Theme` to match your terminal

**Issue**: GIF file too large (>5MB)
- Solution: Reduce dimensions or compress with gifsicle

## Integration

Add demos to README.md:
```markdown
### Quick Start
![Quick Start Demo](demo-vhs/01-quickstart.gif)

### Interactive Shell
![Interactive Shell Demo](demo-vhs/02-interactive-shell.gif)
```

---

Generated with [VHS](https://github.com/charmbracelet/vhs) by Charm
