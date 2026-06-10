import { idbSave } from '../storage/crdt.js';
import { renderMsgs } from '../ui/render.js';

const G = window;

// Crust Cloud W3Bucket API
const CRUST_W3BUCKET_API = 'https://crust-cloud.io/api/v0/w3bucket';

/**
 * Uploads a file (blob/buffer) to Crust Cloud / IPFS.
 * Returns the CID.
 */
export async function uploadToIPFS(data, filename) {
  const blob = data instanceof Blob ? data : new Blob([data], { type: 'application/octet-stream' });
  const formData = new FormData();
  formData.append('file', blob, filename || 'file.bin');

  const r = await fetch(`${CRUST_W3BUCKET_API}/add`, {
    method: 'POST',
    body: formData
  });

  if (!r.ok) throw new Error('Crust upload failed: ' + r.statusText);
  const d = await r.json();
  
  // d.Hash is the CID returned by IPFS via Crust
  return d.Hash;
}

/**
 * Fetches a file from IPFS via a gateway.
 */
export async function fetchFromIPFS(cid) {
  // Using Crust's gateway for reliable access to pinned content
  const gateway = 'https://crust-gateway.io/ipfs/';
  const r = await fetch(gateway + cid);
  if (!r.ok) {
    // Fallback to public gateway if Crust gateway fails
    const publicGateway = 'https://ipfs.io/ipfs/';
    const r2 = await fetch(publicGateway + cid);
    if (!r2.ok) throw new Error('IPFS fetch failed on both gateways');
    const ab = await r2.arrayBuffer();
    return new Uint8Array(ab);
  }
  const ab = await r.arrayBuffer();
  return new Uint8Array(ab);
}
