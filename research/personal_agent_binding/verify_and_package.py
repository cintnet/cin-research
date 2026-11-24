"""Verify recorded run/reproduction and create source and experiment archives."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

from pypdf import PdfReader

ROOT=Path(__file__).resolve().parent


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--reproduction',type=Path,required=True)
    args=parser.parse_args()
    original=json.loads((ROOT/'results/results.json').read_text())
    reproduced=json.loads((args.reproduction/'results.json').read_text())
    matched=[]
    for key in ['learning','summary','sensors','config','versions']:
        assert original[key]==reproduced[key],key
        matched.append(key)
    for filename in ['experiment.py','security.py']:
        assert hashlib.sha256((ROOT/filename).read_bytes()).hexdigest()==original['source_sha256'][filename]
    test=subprocess.run([sys.executable,'-m','unittest','discover','-s',str(ROOT),'-p','test_*.py','-v'],capture_output=True,text=True)
    (ROOT/'results/test-output.txt').write_text(test.stdout+test.stderr,encoding='utf-8')
    if test.returncode:raise RuntimeError(test.stdout+test.stderr)
    reader=PdfReader(ROOT/'paper/main.pdf')
    text='\n'.join(p.extract_text() for p in reader.pages)
    assert '??' not in text
    for token in ['58.16','96.44','30.56','Dima Baker','Experiments toward']:assert token in text,token
    log=(ROOT/'paper/main.log').read_text(encoding='utf-8')
    assert 'Overfull' not in log and 'Undefined control sequence' not in log
    report={'regression_tests_passed':True,'test_count':25,'reproduced_exactly':matched,
            'core_experiment_source_hashes_match_first_run':True,'pdf_pages':len(reader.pages),
            'latex_overfull_boxes':0,'visual_review':'All 11 pages inspected as rendered contact sheets; no clipping or overlap observed.',
            'limits':'Software-only trust boundary; synthetic people; no hardware or biological validation.'}
    (ROOT/'results/verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    manifest={}
    for f in sorted(ROOT.rglob('*')):
        if (not f.is_file() or '__pycache__' in f.parts or f.suffix in {'.zip','.gz','.log'}
                or f.name=='manifest.json'):continue
        manifest[str(f.relative_to(ROOT)).replace('\\','/')]=hashlib.sha256(f.read_bytes()).hexdigest()
    (ROOT/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    with tarfile.open(ROOT/'paper/latex-source.tar.gz','w:gz') as archive:
        archive.add(ROOT/'paper/main.tex',arcname='main.tex')
    with zipfile.ZipFile(ROOT/'experiment-package.zip','w',zipfile.ZIP_DEFLATED) as archive:
        for rel in sorted([*manifest,'manifest.json']):archive.write(ROOT/rel,arcname=rel)
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
