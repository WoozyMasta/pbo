# pbo

Go package for reading, packing, and editing PBO archives.

Main points:

* streaming input API via `Input.Open`
* deterministic pack order by normalized path
* optional LZSS compression by path rules
* pack and hash set in one flow (`PackAndHash*`)
* transactional edit API with backup rotation

## Usage examples

### Pack

`PackFile` writes a deterministic PBO from `[]Input`.
Compression is optional and controlled by path rules. Examples below use `github.com/woozymasta/pathrules`.

```go
inputs := []pbo.Input{
  {
    Path: "config.cpp",
    Open: func() (io.ReadCloser, error) {
      return os.Open("src/config.cpp")
    },
  },
}

opts := pbo.PackOptions{
  Headers: []pbo.HeaderPair{
    {Key: "prefix", Value: "myaddon"},
  },
  Compress: []pathrules.Rule{
    {Action: pathrules.ActionInclude, Pattern: "*.rvmat"},
    {Action: pathrules.ActionInclude, Pattern: "textures/**"},
  },
  CompressMatcherOptions: pathrules.MatcherOptions{
    CaseInsensitive: true,
    DefaultAction:   pathrules.ActionExclude,
  },
  OnEntryDone: func(e pbo.PackEntryProgress) {
    // optional per-entry progress callback
  },
}

res, err := pbo.PackFile(ctx, "addon.pbo", inputs, opts)
if err != nil {
  return err
}

_ = res.WrittenEntries
_ = res.RawBytes
_ = res.CompressedBytes
_ = res.CompressedEntries
_ = res.SkippedCompressionEntries
_ = res.Duration
```

### Compress by extensions

If you only have extension lists, convert them to include rules.

```go
compressExts := []string{"rvmat", "ogg", "paa"}
opts := pbo.PackOptions{
  Compress: pathrules.ParseExtensions(compressExts),
  CompressMatcherOptions: pathrules.MatcherOptions{
    CaseInsensitive: true,
    DefaultAction:   pathrules.ActionExclude,
  },
}
```

You can also load compression rules directly from file:

```go
// compress.rules:
// !*.rvmat
// !textures/**

rules, err := pathrules.LoadRulesFile("compress.rules")
if err != nil {
  return err
}

opts.Compress = rules
```

### Pack and hash

Use `PackAndHashFile` when you need archive creation and hash set in one pass.
This avoids a second read for hash computation.

```go
res, hs, err := pbo.PackAndHashFile(
  ctx,
  "addon.pbo",
  inputs,
  opts,
  pbo.SignVersionV3,
  pbo.GameTypeDayZ,
)
if err != nil {
  return err
}

_ = res
_ = hs
```

### Read and extract

Open archive, read entries by path, and extract to directory in one flow.
`ExtractOptions.MaxWorkers` controls parallel extraction workers.
Path sanitization is enabled by default for `Extract`.

```go
r, err := pbo.Open("addon.pbo")
if err != nil {
  return err
}
defer r.Close()

entries := r.Entries()
data, err := r.ReadEntry(entries[0].Path)
if err != nil {
  return err
}
_ = data

err = r.Extract(ctx, "out", pbo.ExtractOptions{MaxWorkers: 4})
if err != nil {
  return err
}

// Disable default sanitization only when raw names are required.
err = r.Extract(ctx, "out-raw", pbo.ExtractOptions{
  MaxWorkers: 4,
  RawNames:   true,
})
if err != nil {
  return err
}
```

### Edit existing PBO

Use `OpenEditor` for transactional changes to an existing archive.
Queue add/replace/delete operations, then apply once with `Commit`.

```go
editor, err := pbo.OpenEditor("addon.pbo", pbo.EditOptions{
  PackOptions: pbo.PackOptions{
    Compress: []pathrules.Rule{
      {Action: pathrules.ActionInclude, Pattern: "*.txt"},
      {Action: pathrules.ActionInclude, Pattern: "*.c"},
    },
    CompressMatcherOptions: pathrules.MatcherOptions{
      CaseInsensitive: true,
      DefaultAction:   pathrules.ActionExclude,
    },
  },
  BackupKeep: 1,
})
if err != nil {
  return err
}

if err := editor.Replace(pbo.Input{
  Path: "scripts/main.c",
  Open: func() (io.ReadCloser, error) {
    return os.Open("scripts/main.c")
  },
}); err != nil {
  return err
}

if err := editor.DeleteDir("obsolete"); err != nil {
  return err
}

_, err = editor.Commit(ctx)
if err != nil {
  return err
}
```

## Compression behavior

> [!IMPORTANT]  
> In many modern mod packs, compression gives small size reduction.
> Textures and models are usually already compressed by source formats.
> Most gain comes from scripts and text, but they are often a tiny part of
> total archive size. Compressing everything can spend CPU time for marginal
> output difference. Use it selectively when it matches your build goals.
>
> Compression still works correctly in this package.

Compression is considered only when:

* final `PackOptions.Compress` rule decision includes entry path
* size is in `[MinCompressSize, MaxCompressSize]`

Behavior details:

* known-size candidates use in-memory compression path
* unknown-size candidates are written raw
* compressed payload is used only if it is smaller than raw payload

> [!NOTE]  
> Unknown-size inputs are never compressed in the main pack flow.

## Limits and notes

* classic PBO payload addressing is limited to 4 GiB
* pack writes payload sequentially and patches index fields after payload write
* this package does not run source transforms by itself
* caller should provide transformed streams via `Input.Open`
