/* Verity — AI-generated photo checker.
   Reads technical traces inside the image file (metadata, generator
   signatures, content credentials). It does NOT analyze pixels.
   Pure functions are exported for headless tests. */
(function(){
'use strict';

/* ---------- binary helpers ---------- */
function ascii(bytes, start, len){
  var s = '';
  for(var i = 0; i < len; i++) s += String.fromCharCode(bytes[start + i]);
  return s;
}
function u16be(b, o){ return (b[o] << 8) | b[o + 1]; }
function u32be(b, o){ return (b[o] * 16777216) + ((b[o+1] << 16) | (b[o+2] << 8) | b[o+3]); }

/* ---------- PNG ---------- */
function parsePNG(bytes){
  var out = { format: 'PNG', width: 0, height: 0, texts: [], hasC2PA: false };
  if(bytes.length < 8) return out;
  var sig = [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A];
  for(var i = 0; i < 8; i++) if(bytes[i] !== sig[i]) return out;
  var pos = 8;
  while(pos + 8 <= bytes.length){
    var len = u32be(bytes, pos);
    var type = ascii(bytes, pos + 4, 4);
    var dataStart = pos + 8;
    var dataEnd = dataStart + len;
    if(dataEnd + 4 > bytes.length) break;
    if(type === 'IHDR' && len >= 8){
      out.width = u32be(bytes, dataStart);
      out.height = u32be(bytes, dataStart + 4);
    } else if(type === 'tEXt'){
      var z = -1;
      for(var k = dataStart; k < dataEnd; k++) if(bytes[k] === 0){ z = k; break; }
      if(z > 0){
        out.texts.push({
          keyword: ascii(bytes, dataStart, z - dataStart),
          text: ascii(bytes, z + 1, dataEnd - z - 1)
        });
      }
    } else if(type === 'iTXt'){
      /* keyword\0 compFlag compMethod lang\0 transKey\0 text */
      var p = dataStart, zend = -1;
      for(; p < dataEnd; p++) if(bytes[p] === 0){ zend = p; break; }
      if(zend > 0){
        var kw = ascii(bytes, dataStart, zend - dataStart);
        var flag = bytes[zend + 1] || 0;
        var q = zend + 3;
        for(var s = 0; s < 2; s++){ while(q < dataEnd && bytes[q] !== 0) q++; q++; }
        var txt = flag === 0 ? ascii(bytes, q, dataEnd - q) : '[compressed]';
        out.texts.push({ keyword: kw, text: txt });
      }
    } else if(type === 'zTXt'){
      var z2 = -1;
      for(var m = dataStart; m < dataEnd; m++) if(bytes[m] === 0){ z2 = m; break; }
      if(z2 > 0) out.texts.push({ keyword: ascii(bytes, dataStart, z2 - dataStart), text: '[compressed]' });
    } else if(type === 'jumb'){
      out.hasC2PA = true;
    }
    if(type === 'IEND') break;
    pos = dataEnd + 4;
  }
  return out;
}

/* ---------- JPEG / EXIF ---------- */
function readAsciiField(view, le, ifdOff, entryOff){
  var type = view.getUint16(entryOff + 2, le);
  var count = view.getUint32(entryOff + 4, le);
  if(type !== 2 || count === 0 || count > 256) return '';
  var valOff = entryOff + 8;
  var start;
  if(count <= 4){
    start = valOff;
  } else {
    start = view.getUint32(valOff, le);
  }
  var s = '';
  for(var i = 0; i < count - 1; i++){
    var c = view.getUint8(start + i);
    if(c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function parseIFD(view, le, tiffStart, ifdOff, exif){
  if(ifdOff + 2 > view.byteLength) return;
  var count = view.getUint16(ifdOff, le);
  for(var i = 0; i < count; i++){
    var e = ifdOff + 2 + i * 12;
    if(e + 12 > view.byteLength) break;
    var tag = view.getUint16(e, le);
    if(tag === 0x010F) exif.make = readAsciiField(view, le, ifdOff, e);
    else if(tag === 0x0110) exif.model = readAsciiField(view, le, ifdOff, e);
    else if(tag === 0x0131) exif.software = readAsciiField(view, le, ifdOff, e);
    else if(tag === 0x8769){
      var sub = view.getUint32(e + 8, le);
      parseExifIFD(view, le, tiffStart + sub, exif);
    }
  }
}
function parseExifIFD(view, le, ifdOff, exif){
  if(ifdOff + 2 > view.byteLength) return;
  var count = view.getUint16(ifdOff, le);
  for(var i = 0; i < count; i++){
    var e = ifdOff + 2 + i * 12;
    if(e + 12 > view.byteLength) break;
    if(view.getUint16(e, le) === 0x9003) exif.dateTimeOriginal = readAsciiField(view, le, ifdOff, e);
  }
}

function parseJPEG(bytes){
  var out = { format: 'JPEG', width: 0, height: 0,
    exif: { make: '', model: '', software: '', dateTimeOriginal: '' },
    comments: [], hasC2PA: false };
  if(bytes.length < 4 || bytes[0] !== 0xFF || bytes[1] !== 0xD8) return out;
  var pos = 2;
  while(pos + 4 <= bytes.length){
    if(bytes[pos] !== 0xFF) break;
    var marker = bytes[pos + 1];
    pos += 2;
    if(marker === 0xD8 || marker === 0xD9) continue;
    if(marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) continue;
    if(pos + 2 > bytes.length) break;
    var segLen = u16be(bytes, pos);
    if(segLen < 2) break;
    var dataStart = pos + 2, dataEnd = pos + segLen;
    if(dataEnd > bytes.length) break;
    if(marker === 0xE1 && segLen > 8 && ascii(bytes, dataStart, 6) === 'Exif\0\0'){
      try{
        var tiff = dataStart + 6;
        var view = new DataView(bytes.buffer, bytes.byteOffset + tiff, dataEnd - tiff);
        var le;
        var bo = view.getUint16(0, false);
        if(bo === 0x4949) le = true;
        else if(bo === 0x4D4D) le = false;
        else { pos = dataEnd; continue; }
        if(view.getUint16(2, le) !== 42){ pos = dataEnd; continue; }
        var ifd0 = view.getUint32(4, le);
        parseIFD(view, le, tiff, ifd0, out.exif);
      }catch(err){ /* malformed EXIF: ignore */ }
    } else if(marker === 0xFE){
      out.comments.push(ascii(bytes, dataStart, Math.min(segLen - 2, 300)));
    } else if(marker === 0xEB && segLen > 12 && ascii(bytes, dataStart, 5) === 'JUMBF'){
      out.hasC2PA = true;
    }
    if((marker >= 0xC0 && marker <= 0xCF) && marker !== 0xC4 && marker !== 0xC8 && marker !== 0xCC){
      if(segLen >= 7){
        out.height = u16be(bytes, dataStart + 1);
        out.width = u16be(bytes, dataStart + 3);
      }
    }
    if(marker === 0xDA) break; /* start of scan: stop parsing */
    pos = dataEnd;
  }
  if(!out.hasC2PA){
    /* fallback: raw scan for a c2pa box (cheap, may over-match slightly) */
    var hay = ascii(bytes, 0, bytes.length);
    if(hay.indexOf('c2pa') >= 0) out.hasC2PA = true;
  }
  return out;
}

function sniff(bytes){
  if(bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50) return parsePNG(bytes);
  if(bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xD8) return parseJPEG(bytes);
  if(bytes.length >= 12 && ascii(bytes, 4, 4) === 'ftyp') return { format: 'HEIC/AVIF', width: 0, height: 0, texts: [], hasC2PA: false };
  if(bytes.length >= 2 && bytes[0] === 0x42 && bytes[1] === 0x4D) return { format: 'BMP', width: 0, height: 0, texts: [], hasC2PA: false };
  if(bytes.length >= 4 && ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 4) === 'WEBP') return { format: 'WebP', width: 0, height: 0, texts: [], hasC2PA: false };
  return { format: 'Unknown', width: 0, height: 0, texts: [], hasC2PA: false };
}

/* ---------- analysis ---------- */
var AI_KEYWORDS = ['stable diffusion', 'midjourney', 'dall-e', 'dalle', 'firefly',
  'ideogram', 'leonardo', 'comfyui', 'automatic1111', 'novelai', 'civitai',
  'playgroundai', 'kandinsky', 'artbreeder', 'runwayml', 'luma', 'imagen',
  'flux', 'deepai', 'starryai', 'wombo', 'nightcafe', 'bria'];
var PARAM_SIGNS = ['steps:', 'sampler:', 'cfg scale', 'seed:', '"prompt"',
  '"workflow"', 'civitai', 'negative prompt'];

function containsAny(hay, list){
  hay = (hay || '').toLowerCase();
  for(var i = 0; i < list.length; i++) if(hay.indexOf(list[i]) >= 0) return list[i];
  return null;
}

function analyze(parsed){
  var signals = [];
  var score = 0;

  var blob = '';
  (parsed.texts || []).forEach(function(t){ blob += ' ' + t.keyword + ' ' + t.text; });
  if(parsed.exif){
    blob += ' ' + parsed.exif.software;
  }
  (parsed.comments || []).forEach(function(c){ blob += ' ' + c; });

  var kw = containsAny(blob, AI_KEYWORDS);
  if(kw){
    score += 3;
    signals.push({ ai: true, title: 'AI generator named in metadata',
      detail: 'Found "' + kw + '" in the file\u2019s metadata.' });
  }
  var ps = containsAny(blob, PARAM_SIGNS);
  if(ps && !kw){
    score += 3;
    signals.push({ ai: true, title: 'AI generation parameters found',
      detail: 'The file carries generation settings (' + ps.trim() + '), typical of AI image tools.' });
  } else if(ps){
    signals.push({ ai: true, title: 'AI generation parameters found',
      detail: 'The file also carries generation settings (' + ps.trim() + ').' });
  }

  if(parsed.hasC2PA){
    signals.push({ ai: false, title: 'Content Credentials present',
      detail: 'The file has a C2PA manifest. Check the issuer inside it: trusted camera apps sign real photos, AI tools may disclose generation.' });
  }

  var ex = parsed.exif || {};
  if(ex.make || ex.model){
    score -= 3;
    signals.push({ ai: false, title: 'Camera identified',
      detail: 'EXIF names a real camera: ' + (ex.make + ' ' + ex.model).trim() + '.' });
  }
  if(ex.dateTimeOriginal){
    score -= 1;
    signals.push({ ai: false, title: 'Capture timestamp present',
      detail: 'Original date/time recorded: ' + ex.dateTimeOriginal + '.' });
  }

  var hasMeta = blob.replace(/\s+/g, '').length > 0 || parsed.hasC2PA;
  if(!hasMeta){
    signals.push({ ai: null, title: 'No metadata at all',
      detail: 'The file carries no EXIF, comments or text chunks. Many AI images look like this, but so do screenshots and photos stripped by social apps.' });
  }

  var verdict, note;
  if(score >= 2){
    verdict = 'Likely AI-generated';
    note = 'Technical traces in this file point to an AI image tool.';
  } else if(score <= -2){
    verdict = 'Likely a real photo';
    note = 'Technical traces in this file point to a real camera capture.';
  } else {
    verdict = 'Uncertain';
    note = 'No decisive traces either way. Metadata alone cannot prove it.';
  }
  return { verdict: verdict, note: note, signals: signals, score: score };
}

/* ---------- UI wiring (browser only) ---------- */
if(typeof window !== 'undefined' && typeof document !== 'undefined'){
  var $ = function(id){ return document.getElementById(id); };
  var fileInput = $('file'), drop = $('drop'), preview = $('preview'),
      result = $('result'), verdictEl = $('verdict'), noteEl = $('note'),
      sigList = $('signals'), metaEl = $('meta'), toast = $('toast'), toastT = null;

  function showToast(msg){
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(toastT);
    toastT = setTimeout(function(){ toast.classList.remove('show'); }, 1800);
  }
  function fmtBytes(n){
    if(n < 1024) return n + ' B';
    if(n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
  function handleFile(file){
    if(!file) return;
    if(file.size > 25 * 1048576){ showToast('File too large (max 25 MB)'); return; }
    var rd = new FileReader();
    rd.onload = function(){
      var bytes = new Uint8Array(rd.result);
      var parsed = sniff(bytes);
      var a = analyze(parsed);
      preview.src = URL.createObjectURL(file);
      preview.style.display = 'block';
      var cls = a.verdict === 'Likely AI-generated' ? 'v-ai' :
                (a.verdict === 'Likely a real photo' ? 'v-real' : 'v-mid');
      verdictEl.className = 'verdict ' + cls;
      verdictEl.textContent = a.verdict;
      noteEl.textContent = a.note;
      sigList.innerHTML = '';
      a.signals.forEach(function(s){
        var li = document.createElement('li');
        li.className = s.ai === true ? 's-ai' : (s.ai === false ? 's-real' : 's-mid');
        var dot = document.createElement('span'); dot.className = 'dot'; li.appendChild(dot);
        var tx = document.createElement('div');
        var h = document.createElement('strong'); h.textContent = s.title; tx.appendChild(h);
        var p = document.createElement('p'); p.textContent = s.detail; tx.appendChild(p);
        li.appendChild(tx);
        sigList.appendChild(li);
      });
      var dims = parsed.width ? parsed.width + ' × ' + parsed.height + ' px' : 'n/a';
      metaEl.textContent = parsed.format + ' · ' + dims + ' · ' + fmtBytes(file.size);
      result.style.display = 'block';
      result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    };
    rd.readAsArrayBuffer(file);
  }
  drop.addEventListener('click', function(){ fileInput.click(); });
  fileInput.addEventListener('change', function(){ handleFile(fileInput.files[0]); });
  ['dragover','dragenter'].forEach(function(ev){
    drop.addEventListener(ev, function(e){ e.preventDefault(); drop.classList.add('over'); });
  });
  ['dragleave','drop'].forEach(function(ev){
    drop.addEventListener(ev, function(e){ e.preventDefault(); drop.classList.remove('over'); });
  });
  drop.addEventListener('drop', function(e){
    if(e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
  });
}

if(typeof module !== 'undefined' && module.exports){
  module.exports = { parsePNG: parsePNG, parseJPEG: parseJPEG, sniff: sniff, analyze: analyze };
}
})();
