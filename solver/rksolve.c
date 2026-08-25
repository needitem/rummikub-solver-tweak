// rksolve — Rummikub max-tiles-placed solver (Den Hertog & Hulshof DP).
//
// Objective: maximise the number of REAL numbered tiles used on the table,
// subject to (a) every table tile being used (lower bound), (b) not exceeding
// the available tiles (upper bound), (c) all board jokers being placed.
// Rack tiles placed = (max real tiles used) - (numbered tiles already on board).
//
// Sets:  runs  = same colour, >=3 consecutive numbers
//        groups= same number, >=3 distinct colours
// Jokers substitute any single tile in a run or group.
//
// State is swept number by number (1..N). Per colour we carry how many runs end
// at the previous number with length 1, 2, or >=3 (x1,x2,x3); runs of length 1/2
// MUST continue, length>=3 MAY stop. Runs per colour are capped at 2 (two copies
// per tile); jokers can fill positions within those runs.
//
// Build (standalone test):  cc -O2 -o rksolve rksolve.c
// Reads a board/rack spec on stdin (see main) and prints the optimum.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NCOL 4
#define NNUM 13
#define MAXRUN 2          // max simultaneous runs per colour (2 copies)
#define NEG (-1000000)

// ---- per-colour run carry state: (x1,x2,x3) with x1+x2+x3 <= MAXRUN ----
// Enumerate all such triples into a small table.
static int gTriN;                 // number of triples
static int gTri[16][3];           // triple table
static int gTriIdx[3][3][3];      // (x1,x2,x3) -> index

static void buildTriples(void) {
    gTriN = 0;
    memset(gTriIdx, -1, sizeof(gTriIdx));
    for (int a = 0; a <= MAXRUN; a++)
        for (int b = 0; a + b <= MAXRUN; b++)
            for (int c = 0; a + b + c <= MAXRUN; c++) {
                gTri[gTriN][0] = a; gTri[gTriN][1] = b; gTri[gTriN][2] = c;
                gTriIdx[a][b][c] = gTriN; gTriN++;
            }
}

// Problem input.
static int lo[NCOL][NNUM + 1];    // must-use (board) count per colour/number
static int hi[NCOL][NNUM + 1];    // available (board+rack) count
static int jokLo, jokHi;          // joker must-use / available

// State packing: colour triples base gTriN, plus jokers-used 0..jokHi.
// memo[i][packed] : best real tiles from number i onward, or NEG if infeasible.
static int *memo[NNUM + 2];
static long stridePerNum;

static long packColors(int idx[NCOL]) {
    long p = 0;
    for (int k = 0; k < NCOL; k++) p = p * gTriN + idx[k];
    return p;
}

// Enumerate group formations at one number from leftover real tiles per colour
// (rem[]) plus available jokers (jok). Returns via callback the best over all
// group choices: adds (#real tiles consumed by groups) to score, consumes jokers.
// A group = choose g in {0,1,2}; each group is >=3 distinct colours, each colour
// contributes one real tile (if rem>0) or a joker.
//
// We brute force groups greedily by trying group sizes/colour-subsets; counts are
// tiny (<=2 per colour, <=2 jokers), so we enumerate up to 2 groups over subsets.

// Minimum jokers needed to place exactly gc[k] real tiles of each colour at one
// number as valid groups (each group: >=3 tiles, distinct colours or jokers,
// a colour appears at most once per group). Returns -1 if impossible within
// jokBudget. Counts are tiny (gc[k] in 0..2).
static int groupsMinJokers(int gc[NCOL], int jokBudget) {
    int mx = 0, sum = 0, c1 = 0, c2 = 0;
    for (int k = 0; k < NCOL; k++) {
        if (gc[k] < 0 || gc[k] > 2) return -1;
        if (gc[k] > mx) mx = gc[k];
        sum += gc[k];
        if (gc[k] == 1) c1++;
        else if (gc[k] == 2) c2++;
    }
    if (mx == 0) return 0;                 // no groups needed
    int need;
    if (mx == 1) {                         // single group, popcount = sum reals
        int size = sum;                    // distinct colours, each once
        need = size >= 3 ? 0 : (3 - size); // fill with jokers to reach 3
    } else {                               // mx == 2 -> two groups
        // both groups contain the c2 colours; distribute the c1 colours to balance.
        int best = 1e9;
        for (int a = 0; a <= c1; a++) {
            int g1 = c2 + a, g2 = c2 + (c1 - a);
            int j = (g1 >= 3 ? 0 : 3 - g1) + (g2 >= 3 ? 0 : 3 - g2);
            if (j < best) best = j;
        }
        need = best;
    }
    if (need > jokBudget) return -1;
    return need;
}

// forward
static int solve(int i, int cidx[NCOL], int jokUsed);

// At number i, given entering per-colour triples, enumerate run continuations +
// new runs + real/joker fill per colour, then groups across colours.
// We recurse colour by colour to build (real used in runs, joker used, next state,
// leftover real per colour for groups), then handle groups + transition.

static int gBoardNumbered;

static int recurColor(int i, int k, int cidxIn[NCOL],
                      int jokUsed, int nextIdx[NCOL],
                      int realRunSum, int jokRunSum, int realRunArr[NCOL]) {
    if (k == NCOL) {
        int jokLeft = jokHi - jokUsed - jokRunSum;
        // Enumerate per-colour group real consumption gc[k] in [floor_k .. avail_k],
        // floor_k = max(0, lo-realRun) (board tiles that MUST still be placed),
        // avail_k = hi - realRun. Then check groups feasible + maximise total.
        int floorc[NCOL], availc[NCOL];
        for (int c = 0; c < NCOL; c++) {
            int rr = realRunArr[c];
            floorc[c] = lo[c][i] - rr; if (floorc[c] < 0) floorc[c] = 0;
            availc[c] = hi[c][i] - rr;
            if (floorc[c] > availc[c] || floorc[c] > 2) return NEG; // cannot meet board lower bound
            if (availc[c] > 2) availc[c] = 2;
        }
        int best = NEG;
        int gc[NCOL];
        for (gc[0] = floorc[0]; gc[0] <= availc[0]; gc[0]++)
        for (gc[1] = floorc[1]; gc[1] <= availc[1]; gc[1]++)
        for (gc[2] = floorc[2]; gc[2] <= availc[2]; gc[2]++)
        for (gc[3] = floorc[3]; gc[3] <= availc[3]; gc[3]++) {
            int jNeed = groupsMinJokers(gc, jokLeft);
            if (jNeed < 0) continue;
            int gsum = gc[0] + gc[1] + gc[2] + gc[3];
            int nx = solve(i + 1, nextIdx, jokUsed + jokRunSum + jNeed);
            if (nx <= NEG) continue;
            int tot = realRunSum + gsum + nx;
            if (tot > best) best = tot;
        }
        return best;
    }
    int x1 = gTri[cidxIn[k]][0], x2 = gTri[cidxIn[k]][1], x3 = gTri[cidxIn[k]][2];
    int best = NEG;
    for (int c3 = 0; c3 <= x3; c3++) {
        for (int nw = 0; x1 + x2 + c3 + nw <= MAXRUN; nw++) {
            int slots = x1 + x2 + c3 + nw;         // tile-i run slots for colour k
            for (int realRun = 0; realRun <= slots && realRun <= hi[k][i]; realRun++) {
                int jokRun = slots - realRun;
                if (jokUsed + jokRunSum + jokRun > jokHi) continue;
                int nx1 = nw, nx2 = x1, nx3 = x2 + c3;
                if (nx1 + nx2 + nx3 > MAXRUN) continue;
                int idx = gTriIdx[nx1][nx2][nx3];
                if (idx < 0) continue;
                nextIdx[k] = idx;
                realRunArr[k] = realRun;
                int r = recurColor(i, k + 1, cidxIn, jokUsed, nextIdx,
                                   realRunSum + realRun, jokRunSum + jokRun, realRunArr);
                if (r > best) best = r;
            }
        }
    }
    return best;
}

static int solve(int i, int cidx[NCOL], int jokUsed) {
    if (i > NNUM) {
        // all runs must be closed (no length-1/2 pending); jokers must meet lower bound
        for (int k = 0; k < NCOL; k++) {
            if (gTri[cidx[k]][0] != 0 || gTri[cidx[k]][1] != 0) return NEG;
        }
        if (jokUsed < jokLo) return NEG;
        return 0;
    }
    long pc = packColors(cidx);
    long key = pc * (jokHi + 1) + jokUsed;
    if (memo[i][key] != NEG - 1) return memo[i][key];
    int nextIdx[NCOL]; int realRunArr[NCOL];
    for (int k = 0; k < NCOL; k++) { nextIdx[k] = 0; realRunArr[k] = 0; }
    int r = recurColor(i, 0, cidx, jokUsed, nextIdx, 0, 0, realRunArr);
    memo[i][key] = r;
    return r;
}

// ================= Reconstruction =================
// Replays the optimal DP path, rebuilding the actual sets. Open runs are tracked
// per colour; groups are rebuilt per number from the chosen gc[] vector.
static const char *CNAME[NCOL] = { "Black", "Blue", "Red", "Yellow" };

typedef struct { int color, start, len, jokerAt[NNUM + 2], nj; } Run;
static Run openR[NCOL][8]; static int nOpen[NCOL];
static char setsOut[8000]; static int setsLen;
static int realUsed[NCOL][NNUM + 1];

static void emitRun(Run *r) {
    int p = setsLen;
    p += sprintf(setsOut + p, "  RUN %s:", CNAME[r->color]);
    for (int n = r->start; n < r->start + r->len; n++) {
        int isJ = 0; for (int j = 0; j < r->nj; j++) if (r->jokerAt[j] == n) isJ = 1;
        p += sprintf(setsOut + p, " %s", isJ ? "J" : "");
        if (!isJ) p += sprintf(setsOut + p, "%d", n);
    }
    p += sprintf(setsOut + p, "\n");
    setsLen = p;
}

// Choose the optimal decision at (i,cidx,jok): fills per-colour realRun,c3,nw and
// gc[], and the next state; returns 1 on success.
static int chooseDecision(int i, int cidx[NCOL], int jok,
                          int realRunO[NCOL], int c3O[NCOL], int nwO[NCOL],
                          int gcO[NCOL], int nextIdxO[NCOL]) {
    long pc = packColors(cidx); long key = pc * (jokHi + 1) + jok;
    int target = memo[i][key];
    // enumerate per-colour run decisions (recursive) then groups; match target.
    int rr[NCOL], c3[NCOL], nw[NCOL], nextIdx[NCOL];
    // simple nested recursion via explicit stack over colours
    // (counts tiny; brute force)
    int stackk = 0; (void)stackk;
    // We do a plain recursive lambda-like via function pointer is messy in C; unroll with recursion helper:
    // Implement with a manual recursion using an inner function emulation:
    // Instead, do exhaustive loops bounded by MAXRUN per colour.
    // For clarity, recurse:
    // ---- inline recursion ----
    // We'll use a small explicit recursion through an array of states.
    // Colour 0..3, for each try (c3,nw,realRun).
    // Use goto-free nested loops via recursion function below.
    extern int _chooseRec(int, int, int[NCOL], int, int[NCOL], int[NCOL], int[NCOL],
                          int[NCOL], int[NCOL], int, int, int);
    return _chooseRec(i, 0, cidx, jok, realRunO, c3O, nwO, gcO, nextIdxO, 0, 0, target);
}

int _chooseRec(int i, int k, int cidx[NCOL], int jok,
               int realRunO[NCOL], int c3O[NCOL], int nwO[NCOL], int gcO[NCOL],
               int nextIdxO[NCOL], int realRunSum, int jokRunSum, int target) {
    if (k == NCOL) {
        int jokLeft = jokHi - jok - jokRunSum;
        int floorc[NCOL], availc[NCOL];
        for (int c = 0; c < NCOL; c++) {
            int rrk = realRunO[c];
            floorc[c] = lo[c][i] - rrk; if (floorc[c] < 0) floorc[c] = 0;
            availc[c] = hi[c][i] - rrk; if (availc[c] > 2) availc[c] = 2;
            if (floorc[c] > availc[c]) return 0;
        }
        int gc[NCOL];
        for (gc[0] = floorc[0]; gc[0] <= availc[0]; gc[0]++)
        for (gc[1] = floorc[1]; gc[1] <= availc[1]; gc[1]++)
        for (gc[2] = floorc[2]; gc[2] <= availc[2]; gc[2]++)
        for (gc[3] = floorc[3]; gc[3] <= availc[3]; gc[3]++) {
            int jNeed = groupsMinJokers(gc, jokLeft);
            if (jNeed < 0) continue;
            int gsum = gc[0]+gc[1]+gc[2]+gc[3];
            int nx = solve(i + 1, nextIdxO, jok + jokRunSum + jNeed);
            if (nx <= NEG) continue;
            if (realRunSum + gsum + nx == target) {
                for (int c = 0; c < NCOL; c++) gcO[c] = gc[c];
                return 1;
            }
        }
        return 0;
    }
    int x1 = gTri[cidx[k]][0], x2 = gTri[cidx[k]][1], x3 = gTri[cidx[k]][2];
    for (int c3 = 0; c3 <= x3; c3++)
    for (int nw = 0; x1 + x2 + c3 + nw <= MAXRUN; nw++) {
        int slots = x1 + x2 + c3 + nw;
        for (int realRun = 0; realRun <= slots && realRun <= hi[k][i]; realRun++) {
            int jokRun = slots - realRun;
            if (jok + jokRunSum + jokRun > jokHi) continue;
            int nx1 = nw, nx2 = x1, nx3 = x2 + c3;
            if (nx1 + nx2 + nx3 > MAXRUN) continue;
            int idx = gTriIdx[nx1][nx2][nx3]; if (idx < 0) continue;
            realRunO[k] = realRun; c3O[k] = c3; nwO[k] = nw; nextIdxO[k] = idx;
            if (_chooseRec(i, k + 1, cidx, jok, realRunO, c3O, nwO, gcO, nextIdxO,
                           realRunSum + realRun, jokRunSum + jokRun, target))
                return 1;
        }
    }
    return 0;
}

// rebuild groups at number i from gc[] and emit; returns jokers used.
static int emitGroups(int i, int gc[NCOL]) {
    int mx = 0, c1 = 0, c2 = 0;
    for (int k = 0; k < NCOL; k++) { if (gc[k] > mx) mx = gc[k]; if (gc[k]==1) c1++; else if (gc[k]==2) c2++; }
    if (mx == 0) return 0;
    // Build up to `mx` groups. Colour with gc=2 -> both groups; gc=1 -> one group.
    int G = mx; int jok = 0;
    // assign gc=1 colours to balance (greedy: fill group 0 first then 1)
    int grp[2][NCOL]; int gsz[2] = {0,0};
    for (int g = 0; g < 2; g++) for (int k = 0; k < NCOL; k++) grp[g][k] = 0;
    for (int k = 0; k < NCOL; k++) {
        if (gc[k] == 2) { grp[0][k] = 1; grp[1][k] = 1; gsz[0]++; gsz[1]++; }
    }
    for (int k = 0; k < NCOL; k++) if (gc[k] == 1) {
        int g = (G == 1) ? 0 : (gsz[0] <= gsz[1] ? 0 : 1);
        grp[g][k] = 1; gsz[g]++;
    }
    for (int g = 0; g < G; g++) {
        int need = gsz[g] < 3 ? 3 - gsz[g] : 0; jok += need;
        int p = setsLen; p += sprintf(setsOut + p, "  GROUP %d:", i);
        for (int k = 0; k < NCOL; k++) if (grp[g][k]) p += sprintf(setsOut + p, " %s", CNAME[k]);
        for (int j = 0; j < need; j++) p += sprintf(setsOut + p, " J");
        p += sprintf(setsOut + p, "\n"); setsLen = p;
    }
    return jok;
}

static void reconstruct(void) {
    memset(nOpen, 0, sizeof(nOpen)); setsLen = 0; memset(realUsed, 0, sizeof(realUsed));
    int cidx[NCOL] = {0,0,0,0}; int jok = 0;
    for (int i = 1; i <= NNUM; i++) {
        int realRun[NCOL], c3[NCOL], nw[NCOL], gc[NCOL], nextIdx[NCOL];
        for (int k=0;k<NCOL;k++){realRun[k]=c3[k]=nw[k]=gc[k]=0;nextIdx[k]=0;}
        if (!chooseDecision(i, cidx, jok, realRun, c3, nw, gc, nextIdx)) {
            sprintf(setsOut + setsLen, "  (trace failed at %d)\n", i); return;
        }
        int jokRunStep = 0;
        for (int k = 0; k < NCOL; k++) {
            // classify open runs by length
            // continue all len1,len2; c3 of len>=3; close rest; start nw new.
            // rebuild open list
            Run keep[8]; int nk = 0;
            int cont3 = c3[k];
            for (int idx = 0; idx < nOpen[k]; idx++) {
                Run *r = &openR[k][idx];
                int len = i - r->start; // tiles so far (covers start..i-1)
                if (len == 1 || len == 2) { r->len++; keep[nk++] = *r; }
                else { // len>=3
                    if (cont3 > 0) { r->len++; keep[nk++] = *r; cont3--; }
                    else emitRun(r);
                }
            }
            for (int s = 0; s < nw[k]; s++) { Run r; r.color=k; r.start=i; r.len=1; r.nj=0; keep[nk++]=r; }
            // jokers among run slots: slots = x1+x2+c3+nw ; realRun real, rest joker.
            int slots = 0; { int x1=gTri[cidx[k]][0],x2=gTri[cidx[k]][1]; slots=x1+x2+c3[k]+nw[k]; }
            int jokRun = slots - realRun[k];
            jokRunStep += jokRun;
            // mark jokers on the last jokRun kept runs' position i
            for (int t = 0; t < jokRun && t < nk; t++) {
                Run *r = &keep[nk-1-t]; if (r->nj < NNUM) r->jokerAt[r->nj++] = i;
            }
            memcpy(openR[k], keep, sizeof(Run)*nk); nOpen[k] = nk;
            realUsed[k][i] += realRun[k];
        }
        int jokGrp = emitGroups(i, gc);
        for (int k=0;k<NCOL;k++) realUsed[k][i] += gc[k];
        jok += jokRunStep + jokGrp;
        for (int k=0;k<NCOL;k++) cidx[k]=nextIdx[k];
    }
    for (int k = 0; k < NCOL; k++) for (int idx = 0; idx < nOpen[k]; idx++) emitRun(&openR[k][idx]);
}

int main(void) {
    buildTriples();
    // stdin: NCOL lines? We'll hardcode input via a simple format:
    // lines "B c n" (board) or "R c n" (rack); c in 0..3, n in 1..13; "J board_count total_extra"?
    // Simpler: "J b r" sets joker board/rack counts. EOF to solve.
    memset(lo, 0, sizeof(lo)); memset(hi, 0, sizeof(hi)); jokLo = jokHi = 0;
    char line[64];
    while (fgets(line, sizeof(line), stdin)) {
        char t; int a, b;
        if (line[0] == 'J') { sscanf(line, "J %d %d", &a, &b); jokLo = a; jokHi = a + b; continue; }
        if (sscanf(line, "%c %d %d", &t, &a, &b) == 3) {
            if (a < 0 || a >= NCOL || b < 1 || b > NNUM) continue;
            if (t == 'B') { lo[a][b]++; hi[a][b]++; }
            else if (t == 'R') { hi[a][b]++; }
        }
    }
    gBoardNumbered = 0;
    for (int k = 0; k < NCOL; k++) for (int n = 1; n <= NNUM; n++) gBoardNumbered += lo[k][n];

    stridePerNum = 1; for (int k = 0; k < NCOL; k++) stridePerNum *= gTriN;
    stridePerNum *= (jokHi + 1);
    for (int i = 0; i <= NNUM + 1; i++) {
        memo[i] = malloc(sizeof(int) * stridePerNum);
        for (long j = 0; j < stridePerNum; j++) memo[i][j] = NEG - 1;
    }
    int start[NCOL] = {0, 0, 0, 0};
    int best = solve(1, start, 0);
    if (best <= NEG) { printf("INFEASIBLE (board can't be fully arranged with these tiles)\n"); return 0; }
    int rackPlaced = best - gBoardNumbered;
    printf("max real tiles on table = %d\n", best);
    printf("board numbered tiles     = %d\n", gBoardNumbered);
    printf("=> rack tiles placed     = %d\n", rackPlaced);

    reconstruct();
    // tiles to place from rack = realUsed - board(lo), per colour/number
    printf("\nPLACE FROM RACK:\n");
    int shown = 0;
    for (int k = 0; k < NCOL; k++) {
        int any = 0; char buf[256]; int p = 0;
        for (int n = 1; n <= NNUM; n++) {
            int add = realUsed[k][n] - lo[k][n];
            for (int x = 0; x < add; x++) { p += sprintf(buf + p, " %d", n); any = 1; shown++; }
        }
        if (any) printf("  %s:%s\n", CNAME[k], buf);
    }
    if (!shown) printf("  (nothing to place)\n");
    printf("\nRESULTING SETS:\n%s", setsOut);
    return 0;
}
