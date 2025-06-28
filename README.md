# Summaly.cr

Fast web page metadata extraction service written in Crystal, based on [Summaly](https://github.com/misskey-dev/summaly).

## Installation

```bash
git clone https://github.com/ktncode/summaly.cr.git
cd summaly.cr
shards install
make build
```

## Configuration

Create `config.json`:

```json
{
  "bind_addr": "0.0.0.0:3000",
  "timeout": 10000,
  "user_agent": "Summaly.cr/1.0 (+https://github.com/ktncode/summaly.cr)",
  "max_size": 5242880,
  "proxy": null,
  "media_proxy": null,
  "append_headers": []
}
```

## Usage

```bash
export SUMMALY_CONFIG_PATH=./config.json
./bin/summaly
```

### API

```bash
curl "http://localhost:3000/?url=https://example.com"
```

Parameters:
- `url` (required): Target URL
- `lang`: Accept-Language header
- `userAgent`: Custom User-Agent
- `responseTimeout`: Timeout in milliseconds
- `contentLengthLimit`: Max content size in bytes

## License

Mozilla Public License 2.0

## Author

Kotone <git@ktn.works>
