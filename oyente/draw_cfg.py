import graphviz as gv
import functools
from functools import reduce
from opcodes import stack_v
import pprint

def add_nodes(graph, nodes):
    for n in nodes:
        if isinstance(n, tuple):
            graph.node(n[0], **n[1])
        else:
            graph.node(n)
    return graph


def add_edges(graph, edges):
    for e in edges:
        if isinstance(e[0], tuple):
            graph.edge(*e[0], **e[1])
        else:
            graph.edge(*e)
    return graph

def create_graph(n, e, filename):
    digraph = functools.partial(gv.Digraph, format='svg')
    g = add_edges(add_nodes(digraph(), n), e)
    g.render(filename=filename, cleanup=True)
    return g

split_line = '\n' + '=' * 40 + '\n'

def make_label(block, show_constraints):
    label = """{}

line number : ({}, {})

{}

stack sum: {}
block gas: {}
       """.format(
               block.type,
               block.start, block.end,
               '\n'.join(block.instructions),
               block.stksum,
               block.gas)

    if block.acc_gas:
        label += '\naccumulated gas :\n{}\n'.format(
                pprint.pformat(block.acc_gas))

    if show_constraints:
        if block.gas_constraints:
            label += split_line + split_line.join(
                    ["gas_assignment{}:\n{}".format(i + 1, '\n'.join(v)) \
                            for i, v in enumerate(block.gas_constraints.values())])
        if block.path_cond:
            label += split_line + split_line.join(
                    ["path_constraints{}:\n{}".format(
                            i + 1, ',\n'.join(map(str, v)))
                                for i, v in enumerate(block.path_cond.values())])
    if block.source:
        label += split_line + block.source[-1].replace('\n', '\l')
        # label += split_line + split_line.join(block.source)
    else:
        label += split_line + 'no source available'
    return label


def handle_pc(prob_pcs):
    concat = lambda l: reduce(lambda a, b: a + b, l, [])
    prob_pcs["money_concurrency_bug"] = \
        concat(prob_pcs["money_concurrency_bug"])
    prob_pcs["time_dependency_bug"] = \
        [d[i] for d in prob_pcs["time_dependency_bug"] \
                for i in d]
    prob_pcs["assertion_failure"] = \
        [a.pc for a in prob_pcs["assertion_failure"]]
    prob_pcs["integer_underflow"] = \
        [u.pc for u in prob_pcs["integer_underflow"]]
    prob_pcs["integer_overflow"] = \
        [o.pc for o in prob_pcs["integer_overflow"]]
    return prob_pcs

def tag_vulnerability(block, node, pcs):

    weakness = set()
    for key in pcs:
        if [pc for pc in pcs[key] \
                if pc >= block.start \
                and pc <= block.end]:
            weakness.add(key)
    if weakness:
        node[1]['label'] = "vulnerability:{}\n{}".format(
                str(weakness), node[1]['label'])
        node[1]['fillcolor'] = '#ff6666'

    return node

def cfg_nodes(blocks, lgp, show_constraints, src_map, global_problematic_pcs):
    # draw color on longest path
    draw_longest = lambda block: \
            ['#ffffff', '', '#f4f141'][min((block.start in lgp) * 2 \
                                        + bool(block.visited), 2)]

    # draw vulnerability on block
    # draw_vulnerability = lambda block: \
    #        ['#f44242',

    print(global_problematic_pcs)

    pcs = handle_pc(global_problematic_pcs)

    nodes = [(str(block.start), \
             { 'label' : make_label(block, show_constraints), \
                'shape': 'box', \
                'style': 'filled', \
                'fillcolor': draw_longest(block),
             }) for block in blocks]

    for i, (node, block) in enumerate(zip(nodes, blocks)):
        nodes[i] = tag_vulnerability(block, node, pcs)

    return nodes

def cfg_edges(es, lgp, p_cond, show_cond):

    les = list(zip(lgp[:-1], lgp[1:]))
    es = [(b, e) for b in es for e in es[b]]

    return [((str(b), str(e)),
            {'label' : ('\n' + '=' * 40 + '\n').join(p_cond.get((b, e), [])) \
                    if show_cond else '',
             'color': 'red' if (b, e) in les else 'blue'
            }) for (b, e) in es]
