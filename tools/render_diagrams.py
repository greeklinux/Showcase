#!/usr/bin/env python3
"""Render tracked Mermaid blocks in both themes using an external Mermaid CLI."""
import argparse
import json
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mmdc', required=True, help='Path to an installed Mermaid CLI')
    parser.add_argument('--browser', required=True, help='Path to Chrome or Chromium')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    paths = subprocess.check_output(['git', 'ls-files', '*.md'], cwd=root, text=True).splitlines()
    blocks, sources = [], []
    for name in paths:
        text = (root / name).read_text(encoding='utf-8')
        for number, block in enumerate(re.findall(r'^```mermaid\s*\n(.*?)^```', text, re.M | re.S), 1):
            blocks.append('```mermaid\n' + block + '```\n')
            sources.append({'path': name, 'block': number})
    if not blocks:
        raise SystemExit('No Mermaid blocks found')
    out = Path(tempfile.mkdtemp(prefix='showcase-diagrams-'))
    (out / 'source.md').write_text('\n'.join(blocks), encoding='utf-8')
    config = out / 'browser.json'
    config.write_text(json.dumps({'executablePath': str(Path(args.browser).resolve())}))
    command = [str(Path(args.mmdc).resolve()), '-p', str(config)]
    version = subprocess.check_output([command[0], '--version'], text=True).strip()
    broken = out / 'broken.mmd'
    broken.write_text('flowchart TD\n A[broken -->')
    negative = subprocess.run(command + ['-i', str(broken), '-o', str(out / 'broken.svg')], capture_output=True, text=True)
    (out / 'negative.log').write_text(negative.stdout + negative.stderr)
    if negative.returncode == 0 or (out / 'broken.svg').exists():
        raise SystemExit('Renderer did not reject the negative control: ' + str(out))
    results = []
    for theme, background in [('default', 'white'), ('dark', '#0d1117')]:
        target = out / theme
        target.mkdir()
        run = subprocess.run(command + ['-i', str(out / 'source.md'), '-o', str(target / 'diagram.svg'),
                             '-t', theme, '-b', background, '-j', '2'], capture_output=True, text=True)
        (target / 'render.log').write_text(run.stdout + run.stderr)
        if run.returncode:
            raise SystemExit('Render failed: ' + str(target / 'render.log'))
        if len(list(target.glob('*.svg'))) != len(sources):
            raise SystemExit('Unexpected SVG count: ' + str(target))
        for i, source in enumerate(sources, 1):
            svg = target / ('diagram-%d.svg' % i)
            document = ET.parse(svg).getroot()
            if not list(document):
                raise SystemExit('Empty SVG: ' + str(svg))
            width = float(document.attrib['viewBox'].split()[2])
            results.append(dict(source, theme=theme, width=width, needs_width_review=width > 1500))
    report = {'renderer': version, 'blocks': len(sources), 'renders': len(results),
              'negative_control': 'rejected', 'results': results}
    (out / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({'blocks': len(sources), 'renders': len(results), 'negative_control': 'rejected',
                      'wide_renders': sum(r['needs_width_review'] for r in results), 'report': str(out / 'report.json')}))


if __name__ == '__main__':
    main()
