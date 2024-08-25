from igraph import Graph, EdgeSeq, plot
import plotly.graph_objects as go
import pydot
"""
// ---------------------------------------------------------------------------
//
//	Security Advising Modules (SAM) for Cloud IoT and Mobile Ecosystem
//
//  Copyright (C) 2023 Instituto de Telecomunicações (www.it.pt)
//  Copyright (C) 2023 Universidade da Beira Interior (www.ubi.pt)
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 
//  This work was performed under the scope of Project SECURIoTESIGN with funding 
//  from FCT/COMPETE/FEDER (Projects with reference numbers UID/EEA/50008/2013 and 
//  POCI-01-0145-FEDER-030657) 
// ---------------------------------------------------------------------------
"""

################################# FUNCTIONS #################################

"""
[Summary]: Common method to get answer content from module, based on the question text.
[Arguments]: 
    - $questions$: A JSON Object that includes the last session questions of a module.
    - $question_text$: An integer that contains the ID (in DB) of the question.
[Returns]: Answer content for specified question.
"""


def get_answer_content(questions, question_id):
    for question in questions:
        if question['id'] == question_id:
            answers = question['answer']
            if len(answers) == 1:
                answer = answers[0]['content']
            else:
                answer = []
                for ans in answers:
                    answer.append(ans['content'])
            return answer

    return []


"""
[Summary]: Common method to get recommendation id by comparing its content with the recommendation name.
[Arguments]: 
    - $recommendations$: A JSON Object that includes information about recommendations.
    - $recommendation_name$: A string that contains a recommendation name (content in JSON).
[Returns]: Recommendation ID.
"""


def get_recommendation_id(recommendations, recommendation_name):
    for rec in recommendations:
        if rec['content'] == recommendation_name:
            return rec['id']

    return None


"""
[Summary]: Common method to get answers from a dependency module.
[Arguments]: 
    - $number_id$: A integer that contains the dependency module ID.
[Returns]: Set of answers.
"""


def get_module_answers(number_id, session):
    modules = session['dependencies']
    for i in range(len(modules)):
        module = modules[i]['module']
        if module['id'] == number_id:
            return module

    return {}


# Define the nodes and edges of the attack tree
nodes = {
    'Component': {'Device', 'Data', 'Communications and Networking', 'User', 'Application'},
    'Device': {'Physical Tampering', 'Physical Damage', 'Theft', 'Side-Channel Attacks', 'Reverse Engineering',
               'Sleep Deprivation', 'Jamming and Interference'},
    'Data':{'Data Tampering', 'Data Theft', 'Replay', 'Poisoning', 'Injection'},
    'Communications and Networking': {'Traffic Analysis', 'Eavesdropping', 'Spoofing', 'Denial of Service',
                                      'Man-in-the-Middle', 'Sniffing', 'Flooding', 'Sinkhole', 'Node Injection',
                                      'Sybil'},
    'User': {'Social Engineering', 'Brute Force', 'Misconfiguration', 'Pharming'},
    'Application': {'Denial of Service', 'Virus and Worms', 'Malware', 'SQL Injection', 'Cross-Site Scripting', 'Session Hijacking', 'Spoofing'}
}

nodes1 = {
    'Physical Tampering': {'Access Device', 'Interfere with Device'},
    'Access Device': {'Physically Open Device', 'Connect to Exposed Port'},
    'Physically Open Device': {'Remove Component from Device', 'Probe Conductors', 'Access Hardware Component'},
    'Connect to Exposed Port': {'Read from Device','Write to Device'},
    'Remove Component from Device': {'Obtain firmware and sensitive data'},
    'Probe Conductors': {'Retrieve sensitive data, e.g., encryption keys, exposed data'},
    'Access Hardware Component': {'Identify components with potential vulnerabilities', 'Reverse engineer device'}
}

tree_tampering = {'Physical Tampering':
                      {'Access Device': {
                          'Physically Open Device': {
                                'Remove Component from Device': {'Obtain firmware and sensitive data'},
                                'Probe Conductors': {'Retrieve sensitive data, e.g., encryption keys, exposed data'},
                                'Access Hardware Component': {'Identify components with potential vulnerabilities', 'Reverse engineer device'}
                          },
                          'Connect to Exposed Port': {'Read from Device', 'Write to Device'}
                                 }
                      }
                 }


def draw(parent_name, child_name):
    edge = pydot.Edge(parent_name, child_name)
    graph.add_edge(edge)


def visit(node, parent=None):
    for k, v in node.items():# If using python3, use node.items() instead of node.iteritems()
        if isinstance(v, dict):

            # We start with the root node whose parent is None
            # we don't want to graph the None node
            if parent:
                draw(parent, k)
            visit(v, k)
        else:
            draw(parent, k)
            # drawing the label using a distinct name
            draw(k, str(k)+'_'+str(v))


def visitDict(nodes_dict, parent=None):

    if parent is None:
        #for n, c in nodes_dict.items():
        n = list(nodes_dict.keys())[0]
        c = list(nodes_dict.get(n))
        for a in list(c):
            if a is not None:
                draw(n, a)
                visitDict(nodes_dict, a)
    else:
        n = nodes_dict.get(parent)
        if n is not None:
            for a in list(n):
                draw(parent, a)
                visitDict(nodes_dict, a)


graph = pydot.Dot(graph_type='digraph')
visitDict(nodes1)
graph.set_name("Tampering")
graph.write_png('physical_tampering.png')

"""edges = [(0, 1),
 (1, 2),
 (2, 3),
 (2, 4),
 (2, 5),
 (2, 6),
 (0, 7),
 (7, 8),
 (7, 9),
 (7, 10),
 (10, 11),
 (10, 12),
 (10, 13),
 (10, 14)]
tree = Graph.Tree_Game(n=2)
tree.vs['label'] = [v.index for v in tree.vs]
plot(tree, layout=tree.layout('rt', root=[0]), bbox=(300,300))


nr_vertices = 15
v_label = list(map(str, range(nr_vertices)))
print(v_label)
G = Graph(edges=edges)
#G = Graph.Tree(nr_vertices, 1) # 2 stands for children number
lay = G.layout('rt')

position = {k: lay[k] for k in range(nr_vertices)}
print(lay)
Y = [lay[k][1] for k in range(nr_vertices)]
M = max(Y)

es = EdgeSeq(G) # sequence of edges
E = [e.tuple for e in G.es] # list of edges
E = edges
L = len(position)
Xn = [position[k][0] for k in range(L)]
Yn = [2*M-position[k][1] for k in range(L)]
Xe = []
Ye = []
for edge in E:
    Xe+=[position[edge[0]][0],position[edge[1]][0], None]
    Ye+=[2*M-position[edge[0]][1],2*M-position[edge[1]][1], None]

labels = v_label

fig = go.Figure()
fig.add_trace(go.Scatter(x=Xe,
                   y=Ye,
                   mode='lines',
                   line=dict(color='rgb(210,210,210)', width=1),
                   hoverinfo='none'
                   ))
fig.add_trace(go.Scatter(x=Xn,
                  y=Yn,
                  mode='markers',
                  name='bla',
                  marker=dict(symbol='circle-dot',
                                size=18,
                                color='#6175c1',    #'#DB4551',
                                line=dict(color='rgb(50,50,50)', width=1)
                                ),
                  text=labels,
                  hoverinfo='text',
                  opacity=0.8
                  ))

def make_annotations(pos, text, font_size=10, font_color='rgb(250,250,250)'):
    L=len(pos)
    if len(text)!=L:
        raise ValueError('The lists pos and text must have the same len')
    annotations = []
    for k in range(L):
        annotations.append(
            dict(
                text=labels[k], # or replace labels with a different list for the text within the circle
                x=pos[k][0], y=2*M-position[k][1],
                xref='x1', yref='y1',
                font=dict(color=font_color, size=font_size),
                showarrow=False)
        )
    return annotations

axis = dict(showline=False, # hide axis line, grid, ticklabels and  title
            zeroline=False,
            showgrid=False,
            showticklabels=False,
            )

fig.update_layout(title= 'Tree with Reingold-Tilford Layout',
              annotations=make_annotations(position, v_label),
              font_size=12,
              showlegend=False,
              xaxis=axis,
              yaxis=axis,
              margin=dict(l=40, r=40, b=85, t=100),
              hovermode='closest',
              plot_bgcolor='rgb(248,248,248)'
              )

fig.show()"""
