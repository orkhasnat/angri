from tqdm import tqdm


def get_data(file, T):
    cnt = 0
    st1 = set()
    st2 = set()
    with open(file, 'r') as f:
        #rint(f.readlines())
        lines = f.readlines()[1:]
        for line in lines:
            line = line.strip()
            u, v, w = line.split(',')
            w = w.replace('%', '')
            w = float(w)
            st1.add(u)
            st2.add(v)
            if w >= T:
                cnt += 1
    return cnt, max(len(st1), len(st2))

def brute_match(graph, n1, n2, T = 70):
    if n1 == 0 or n2 == 0:
        return 0

    graph = sorted(graph)[::-1]
    vis1 = [False for _ in range(n1)]
    vis2 = [False for _ in range(n2)]

    totalMatch = 0
    cnt = 0
    for w, v1, v2 in graph:
        if vis1[v1] or vis2[v2]:
            continue
        # if w > T:
        #     cnt += 1
        totalMatch += w
        vis1[v1] = True
        vis2[v2] = True
    #print(totalMatch)
    #return (cnt / max(n1, n2)) * 100
    return totalMatch / max(n1, n2)

M = {
    'TP': 0, 'TN' : 0,
    'FP': 0, 'FN' : 0

}

def similarity(file, T):
    match_funcs, tot = get_data(file, T)
    unmatch = tot - match_funcs
    score = unmatch/tot
    print(score)
    return score
    #print(edges)
    score = brute_match(edges, n1, n2, 60)
    # print(score)
    if score >= T:
        v = 1
    else:
        v = 0
    b1, b2 = file.split('/')[-1].split('_')
    b2 = b2.split('.')[0]
    #print(b1, b2, score, v)
    return v
    global M
    if b1 == b2:
        if v:
            M['TP'] += 1
        else:
            M['FN'] += 1
    else:
        if v:
            M['FP'] += 1
        else:
            M['TN'] += 1

if __name__ == "__main__":
    compilers = ["gcc","clang"]
    optimizations = ["O1", "Og"]
    #bins = "cat  cp  cut  date  df  du  echo  ghost  head  ln  ls  mkdir  mv  pwd  rm  rmdir  sort  tail  uname  who".split()
    #bins = ["date", "ghost", "uname"]
    bins = ["cat", "cp", "cut", "date", "ghost", "uname"]
    
    T = 90
    cnt = 0
    score = 0
    for i in tqdm(range(len(bins))):
        for j in tqdm(range(i,len(bins))):
            bin1 = bins[i]
            bin2 = bins[j]
            
            for k in range(len(optimizations)):
                for l in range(k, len(optimizations)):
                    opt1 = optimizations[k]
                    opt2 = optimizations[l]
                    for m in range(len(compilers)):
                        for n in range(m, len(compilers)):
                            c1 = compilers[m]
                            c2 = compilers[n]
                            if bin1 == bin2: continue
                            try:
                                file = f'output/{c1}_{c2}/{opt1}_{opt2}/{bin1}_{bin2}.csv'
                                score += similarity(file, T)
                                cnt += 1
                                #result = testing(f"test/coreutils/{c1}/x86/{opt1}/{bin1}",f"test/coreutils/{c2}/x86/{opt2}/{bin2}")
                                #safe_to_csv(result,f"output/{c1}_{c2}/{opt1}_{opt2}/{bin1}_{bin2}.csv")
                            except Exception as e:
                                #print(f"{c1} - {c2} / {opt1} - {opt2} / {bin1} - {bin2} failed")
                                #print(e)
                                pass
     
    #tot = M['TP'] + M['TN'] + M['FP'] + M['FN']
    #tru = M['TP'] + M['TN']
    accuracy = (score / cnt) * 100
    #print(cnt, score)
    print(accuracy)
    #print(cnt)