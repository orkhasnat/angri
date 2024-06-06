import angr

class Similarity:
    def __init__(self, bin1, bin2, binary_location, verbose = False):
        self.bin1 = bin1
        self.bin2 = bin2
        self.location = binary_location
        self.proj = angr.Project(self.location, load_options={"auto_load_libs": False})
        self.verbose = verbose


    def constraint_similarity(self, c1, c2):
        if isinstance(c1, tuple):
            c1 = c1[0]
        if isinstance(c2, tuple):
            c2 = c2[0]
        
        state = self.proj.factory.entry_state()
        state.solver.add(c1 != c2)

        return 1 if not state.satisfiable() else 0

    def brute_match(self, graph, n1, n2):
        if(n1 == 0 or n2 == 0): return 0

        graph = sorted(graph)[::-1]
        vis1 = [False for _ in range(n1)]
        vis2 = [False for _ in range(n2)]
        
        totalMatch = 0
        for w, v1, v2 in graph:
            if vis1[v1] or vis2[v2]: continue
            
            totalMatch += w
            vis1[v1] = True
            vis2[v2] = True
        
        return totalMatch / max(n1, n2)

    def array_similarity(self, ara1, ara2, element_similarity):
        n1 = len(ara1)
        n2 = len(ara2)
        if(n1 == 0 or n2 == 0): return 0

        edgList = []
        for u, elem1 in enumerate(ara1):
            for v, elem2 in enumerate(ara2):
                w = element_similarity(elem1, elem2)
                if w > 0: edgList.append((w, u, v))
        
        return self.brute_match(edgList, n1, n2)

    def isequal(self, c1, c2):
        if type(c1) != type(c2): return 0
        else:
            try:
                return self.constraint_similarity(c1, c2)
            except:
                return 0

    def LCS(self, constraints1, constraints2):
        m, n = len(constraints1), len(constraints2)
        db = [0] * (max(m, n) + 100)  # db is initialized to all zeros

        for i in range(1, m + 1):
            prev = db[0]
            for j in range(1, n + 1):
                temp = db[j]
                if self.isequal(constraints1[i - 1], constraints2[j - 1]):
                    db[j] = 1 + prev
                else:
                    db[j] = max(db[j - 1], db[j])
                prev = temp

        return max(db) / max(m, n)

    # need to parallelize it.
    # optionally add timeout to constraint similarity
    def path_similarity(self, path1, path2):
        #constraints1, constraints2 = [], []
        c1 = []
        c2 = []
        for id1, elem1 in enumerate(path1):
            if isinstance(elem1, tuple): elem1 = elem1[0]
            c1.append(elem1)
        
        for id2, elem2 in enumerate(path2):
            if isinstance(elem2, tuple): elem2 = elem2[0]
            c2.append(elem2)
                
        return self.LCS(c1, c2)

    def function_similarity(self, f1, f2):
        paths1, paths2 = [], []
        
        for path in f1:
            if len(path) > 0: paths1.append(path)
        
        for path in f2:
            if len(path) > 0: paths2.append(path)

        return self.array_similarity(paths1, paths2, self.path_similarity)
        #return self.array_similarity(f1, f2, self.path_similarity)

    def binary_similarity(self):
        confusion = {}
        for fun1, paths1 in self.bin1.items():
            confusion[fun1] = {}
            for fun2, paths2 in self.bin2.items():
                
                score = self.function_similarity(paths1, paths2)
                confusion[fun1][fun2] = f'{score: .3%}'
                if self.verbose:
                    print(f'Compared {fun1} and {fun2} with {score: .3%}')

        return confusion