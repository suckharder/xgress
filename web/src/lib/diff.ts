export type DiffLine = { type: "same" | "add" | "del"; text: string };

export function stringify(v: unknown): string {
  return JSON.stringify(v, null, 2);
}

// A compact LCS line diff between two strings — used to show config snapshot diffs.
export function diffLines(oldStr: string, newStr: string): DiffLine[] {
  const a = oldStr.split("\n");
  const b = newStr.split("\n");
  const m = a.length, n = b.length;
  // LCS length table.
  const lcs: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0, j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) { out.push({ type: "same", text: a[i] }); i++; j++; }
    else if (lcs[i + 1][j] >= lcs[i][j + 1]) { out.push({ type: "del", text: a[i] }); i++; }
    else { out.push({ type: "add", text: b[j] }); j++; }
  }
  while (i < m) { out.push({ type: "del", text: a[i++] }); }
  while (j < n) { out.push({ type: "add", text: b[j++] }); }
  return out;
}
