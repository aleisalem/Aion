#!/usr/bin/python

from Aion.utils.data import *
from Aion.utils.graphics import *
from Aion.utils.misc import *

import numpy as np
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA

import plotly.plotly as py
from plotly.offline import plot, iplot
from plotly.graph_objs import *

def reduceAndVisualize(X, y, dim=2, reductionAlgorithm="tnse", figSize=(1024,1024), figTitle="Data visualization", appNames=[], saveProjectedData=False):
    """
    Generates a scatter plot using "plotly" after projecting the data points into <dim>-dimensionality using tSNE or PCA
    :param X: The matrix containing the feature vectors
    :type X: list
    :param y: The labels of the feature vectors
    :type y: list
    :param dim: The target dimensionality to project the feature vectors to (default=2)
    :type dim: int
    :param reductionAlgorithm: The algorithm to use for dimensionality reduction
    :type reductionAlgorithm: str
    :param figSize: The size of the figure
    :type figSize: tuple (of ints)
    :param figTitle: The title of the figure and the name of the resulting HTML file
    :type figTitle: str
    :param appNames: The names of apps to be used as tooltips for each data point. Assumed to match one-to-one with the feature vectors in X
    :type appNames: list of str
    :param saveProjectedData: Whether to save the projected data in a CSV file
    :type saveProjectedData: bool
    :return: A bool depicting the success/failure of the operaiton
    """
    try:
        # Prepare data
        X, y = np.array(X), np.array(y)
        # Build model
        reductionModel = TSNE(n_components=dim) if reductionAlgorithm == "tsne" else None
        # Apply transformation
        prettyPrint("Projecting %s feature vectors of dimensionality %s into %s-d" % (X.shape[0], X.shape[1], dim))
        X_new = reductionModel.fit_transform(X)
        # Generate a scatter plot
        prettyPrint("Populating the traces for malware and goodware")
        x_mal, y_mal, x_good, y_good = [], [], [], []
        labels_mal, labels_good = [], []
        if dim == 3:
            z_mal, z_good = [], []
        for index in range(len(y)):
            if y[index] == 1:
                x_mal.append(X_new[index][0])
                y_mal.append(X_new[index][1])
                if dim == 3:
                    z_mal.append(X_new[index][2])
                labels_mal.append(appNames[index])
            else:
                x_good.append(X_new[index][0])
                y_good.append(X_new[index][1])
                if dim == 3:
                    z_good.append(X_new[index][2])
                labels_good.append(appNames[index])

        # Create traces for the scatter plot 
        prettyPrint("Creating a scatter plot")
        if dim == 2:
            # The trace for malware
            trace_malware = Scatter(x=x_mal,
               y=y_mal,
               mode='markers',
               name='Malware',
               marker=Marker(symbol='dot',
                             size=6,
                             color='red',
                             opacity=0.75,
                             line=Line(width=2.0)
                             ),
               hoverinfo='text',
               text=labels_mal
               )
            # The trace for goodware    
            trace_goodware = Scatter(x=x_good,
                y=y_good,
                mode='markers',
                name='Goodware',
                marker=Marker(symbol='dot',
                              size=6,
                              color='blue',
                              opacity=0.75,
                              line=Line(width=2.0)
                              ),
                hoverinfo='text',
                text=labels_good
                )
        elif dim == 3:
            # The trace for malware
            trace_malware = Scatter3d(x=x_mal,
                y=y_mal,
                z=z_mal,
                mode='markers',
                name='Malware',
                marker=Marker(symbol='dot',
                              size=6,
                              color='red',
                              opacity=0.5,
                              line=Line(width=1.0)
                              ),
                hoverinfo='text',
                text=labels_mal
                )
            # The trace for goodware    
            trace_goodware = Scatter3d(x=x_good,
                y=y_good,
                z=z_good,
                mode='markers',
                name='Goodware',
                marker=Marker(symbol='dot',
                              size=6,
                              color='blue',
                              opacity=0.5,
                              line=Line(width=1.0)
                              ),
                hoverinfo='text',
                text=labels_good
                )
        # Define the axis properties
        axis=dict(showbackground=False,
            showline=False, # hide axis line, grid, ticklabels and  title
            zeroline=False,
            showgrid=False,
            showticklabels=False,
            visible=False,
            title=''
            )
        # Define the figure's layout
        layout=Layout(title=figTitle,
            width=figSize[0],
            height=figSize[1],
            font= Font(size=12),
            showlegend=True,
            scene=Scene(
                xaxis=XAxis(axis),
                yaxis=YAxis(axis),
                zaxis=ZAxis(axis)
            ),
            margin=Margin(
                t=100,
            ),
            hovermode='closest',
            annotations=Annotations([
                Annotation(
                showarrow=False,
                text=figTitle,
                xref='paper',
                yref='paper',
                x=0,
                y=0.1,
                xanchor='left',
                yanchor='bottom',
                font=Font(
                    size=14
                    )
                )
                ]),
            )
        # Generate graph file
        data=Data([trace_malware, trace_goodware])
        fig=Figure(data=data, layout=layout)
        plot(fig, filename=figTitle.lower().replace(' ', '_'))


    except Exception as e:
        prettyPrintError(e)
        return False

    return True



