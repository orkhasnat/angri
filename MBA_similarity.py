import angr
import z3
import claripy

class Similarity:
    def __init__(self, bin1, bin2, binary_location, verbose = False):
        self.bin1 = bin1
        self.bin2 = bin2
        self.location = binary_location
        self.proj = angr.Project(self.location, load_options={"auto_load_libs": False})
        self.verbose = verbose

    def simplify_name(self, name):
        id = name.split('_')[-2]
        if 'reg' in name:
            simplified_name = 'r' + id
        else:
            simplified_name = 'm' + id
        return simplified_name

    def ast_to_math_expr(self, ast):
        #print(ast.op, ast.args)
        if ast.op == 'BVV':
            return str(ast.args[0])

        elif ast.op == 'BVS':
            return self.simplify_name(ast.args[0])

        elif ast.op in {'__add__', '__sub__', '__mul__', '__div__', '__mod__',
                        '__and__', '__or__', '__xor__', '__lshift__', '__rshift__'}:
            # Binary operations
            left = self.ast_to_math_expr(ast.args[0])
            #print(left, 'lololol', ast.args[0].args, ast.args[0].op)
            right = self.ast_to_math_expr(ast.args[1])
            #print(left, right)
            op = {
                '__add__': '+',
                '__sub__': '-',
                '__mul__': '*',
                '__div__': '/',
                '__mod__': '%',
                '__and__': '&',
                '__or__': '|',
                '__xor__': '^',
                '__lshift__': '<<',
                '__rshift__': '>>'
            }[ast.op]
            return f"({left}  {op}  {right})"
        
        elif ast.op == 'Extract':
            return self.ast_to_math_expr(ast.args[2])

        elif ast.op == '__invert__':
            # Unary operation
            operand = self.ast_to_math_expr(ast.args[0])
            return f"~{operand}"

        else:
            #print('beans', ast.args)
            # Other operations can be added here as needed
            return self.ast_to_math_expr(ast.args[1])
        
    def is_equal(self, leftExpre, rightExpre, bitnumber=2):
        """check the relaion whether the left expression is euqal to the right expression.
        Args:
            leftExpre: left expression.
            rightExpre: right expression.
            bitnumber: the number of the bits of the variable.
        Returns:
            True: equation.
            False: unequal.
        Raises:
            None.
        """
        r_vars = z3.BitVecs(' '.join(f'r{i}' for i in range(1, 201)), bitnumber)

        # Declare m1 to m200 BitVec variables
        m_vars = z3.BitVecs(' '.join(f'm{i}' for i in range(1, 201)), bitnumber)

        # Unpack the variables if needed individually
        r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30, \
        r31, r32, r33, r34, r35, r36, r37, r38, r39, r40, r41, r42, r43, r44, r45, r46, r47, r48, r49, r50, r51, r52, r53, r54, r55, r56, r57, r58, \
        r59, r60, r61, r62, r63, r64, r65, r66, r67, r68, r69, r70, r71, r72, r73, r74, r75, r76, r77, r78, r79, r80, r81, r82, r83, r84, r85, r86, \
        r87, r88, r89, r90, r91, r92, r93, r94, r95, r96, r97, r98, r99, r100, r101, r102, r103, r104, r105, r106, r107, r108, r109, r110, r111, r112, \
        r113, r114, r115, r116, r117, r118, r119, r120, r121, r122, r123, r124, r125, r126, r127, r128, r129, r130, r131, r132, r133, r134, r135, \
        r136, r137, r138, r139, r140, r141, r142, r143, r144, r145, r146, r147, r148, r149, r150, r151, r152, r153, r154, r155, r156, r157, r158, \
        r159, r160, r161, r162, r163, r164, r165, r166, r167, r168, r169, r170, r171, r172, r173, r174, r175, r176, r177, r178, r179, r180, r181, \
        r182, r183, r184, r185, r186, r187, r188, r189, r190, r191, r192, r193, r194, r195, r196, r197, r198, r199, r200 = r_vars

        m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, \
        m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, \
        m59, m60, m61, m62, m63, m64, m65, m66, m67, m68, m69, m70, m71, m72, m73, m74, m75, m76, m77, m78, m79, m80, m81, m82, m83, m84, m85, m86, \
        m87, m88, m89, m90, m91, m92, m93, m94, m95, m96, m97, m98, m99, m100, m101, m102, m103, m104, m105, m106, m107, m108, m109, m110, m111, \
        m112, m113, m114, m115, m116, m117, m118, m119, m120, m121, m122, m123, m124, m125, m126, m127, m128, m129, m130, m131, m132, m133, m134, \
        m135, m136, m137, m138, m139, m140, m141, m142, m143, m144, m145, m146, m147, m148, m149, m150, m151, m152, m153, m154, m155, m156, m157, \
        m158, m159, m160, m161, m162, m163, m164, m165, m166, m167, m168, m169, m170, m171, m172, m173, m174, m175, m176, m177, m178, m179, m180, \
        m181, m182, m183, m184, m185, m186, m187, m188, m189, m190, m191, m192, m193, m194, m195, m196, m197, m198, m199, m200 = m_vars

        leftEval = eval(leftExpre)
        #print(leftEval, rightExpre)
        rightEval = eval(rightExpre)

    

        #leftEval = z3.simplify(leftEval)
        #rightEval = z3.simplify(rightEval)

        solver = z3.Solver()
        solver.add(leftEval != rightEval)
        result = solver.check()

        #return result

        if str(result) == "sat":
            return 0
        else:
            return 1

    def constraint_similarity_old(self, c1, c2):
        if isinstance(c1, tuple):
            c1 = c1[0]
        if isinstance(c2, tuple):
            c2 = c2[0]
        
        state = self.proj.factory.entry_state()
        state.solver.add(c1 != c2)

        return 1 if not state.satisfiable() else 0


    def constraint_similarity(self, c1, c2):
        #print(c1, c2)
        if isinstance(c1,claripy.ast.bool.Bool):
            return self.constraint_similarity_old(c1, c2)

        c1, c2 = self.ast_to_math_expr(c1), self.ast_to_math_expr(c2)
        return self.is_equal(c1, c2)

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


    # need to parallelize it.
    # optionally add timeout to constraint similarity
    def path_similarity(self, path1, path2):
        #constraints1, constraints2 = [], []
        edgeList = []
        for id1, elem1 in enumerate(path1):
            if isinstance(elem1, tuple): elem1 = elem1[0]
            for id2, elem2 in enumerate(path2):
                #print(elem2)
                if isinstance(elem2, tuple): elem2 = elem2[0]
                if type(elem1) != type(elem2): continue
                #print(elem1, elem2)
                isSimilar = self.constraint_similarity(elem1, elem2)
                if isSimilar:
                    edgeList.append((1, id1, id2))
                
        return self.brute_match(edgeList, len(path1), len(path2))

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