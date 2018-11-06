import graphviz as gv
import functools
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

def cfg_nodes(blocks, lgp, show_cond, src_map):
    color = lambda tag, cover: \
            ['#ffffff', '', '#f4f141'][min((tag in lgp) * 2 + bool(cover), 2)]
    cond = lambda show, cons: ('\n' + '=' * 40 + '\n') + \
            ('\n' + '=' * 40 + '\n').join(cons) if cons and show else ''
    acc_gas = lambda g: 'accumulated gas : ' + pprint.pformat(g) + '\n\n' if g else ''

    # addIdx = lambda inst, addrs: '\n'.join(inst)
    notaddIdx = lambda inst, addrs: \
            '\n'.join(["%s" % inst \
            for (idx,inst) in zip(addrs, inst)]) \
            if len(inst) == len(addrs) else '\n'.join(inst)
    addIdx = lambda inst, addrs: \
            '\n'.join(["%d:%s" % (idx, inst) \
            for (idx,inst) in zip(addrs, inst)]) \
            if len(inst) == len(addrs) else '\n'.join(inst)

    return [(str(block.start), \
             { 'label' : \
                 """%s\naddrs : (%s, %s)\n\n%s\n\n%s\n%s\n%s%s%s%s""" % (
                    block.type,
                    block.start, block.end,
                    notaddIdx(block.instructions,
                              block.addrs),
                    "stack sum: " + str(block.stksum),
                    'block gas : ' + str(block.gas),
                    acc_gas(block.acc_gas),
                    cond(show_cond, ["gas_assignment{}:\n{}".format(i + 1, '\n'.join(v))\
                            for i, v in enumerate(block.gas_constraints.values())]),
                    # '\n' + '=' * 40 + "\nacc_gas_constraints:\n" + \
                    # block.acc_gas_constraints \
                    # if block.acc_gas_constraints else '',
                    cond(show_cond,
                        ["path_constraints{}:\n{}".format(
                            i + 1,
                            ',\n'.join(map(str, v)))
                                for i, v in enumerate(block.path_cond.values())]),
                    "\n{}\n{}".format('-' * 40, block.source[-1])
                    ),
                'shape': 'box', \
                'style': 'filled', \
                'fillcolor': color(block.start, block.visited),
             }) for block in blocks]

def cfg_edges(es, lgp, p_cond, show_cond):

    les = list(zip(lgp[:-1], lgp[1:]))
    es = [(b, e) for b in es for e in es[b]]

    return [((str(b), str(e)),
            {'label' : ('\n' + '=' * 40 + '\n').join(p_cond.get((b, e), [])) \
                    if show_cond else '',
             'color': 'red' if (b, e) in les else 'blue'
            }) for (b, e) in es]
