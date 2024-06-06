import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


class Visualize:
    def __init__(self, matrix, name1, name2, typ):
        self.df = pd.DataFrame(matrix)
        print(self.df)
        self.df = self.df.applymap(lambda x: float(x.strip("%")) / 100 if isinstance(x, str) and '%' in x else x)
        self.name1 = name1
        self.name2 = name2
        self.typ = typ

    def plot_confusion_matrix(self, figsize=(8, 6), cmap="Blues"):
        confusion_matrix = self.df
        plt.figure(figsize=figsize)
        plt.imshow(confusion_matrix, interpolation='nearest', cmap=cmap)
        plt.title(self.typ)
        plt.colorbar()
        
        # Dynamic tick marks based on matrix dimensions
        tick_marks_x = np.arange(confusion_matrix.shape[1])
        tick_marks_y = np.arange(confusion_matrix.shape[0])
        
        plt.xticks(tick_marks_x, confusion_matrix.columns, rotation=45)
        plt.yticks(tick_marks_y, confusion_matrix.index)
        
        # Number formatting inside the cells and dynamic threshold for text color
        fmt = ".2f" if confusion_matrix.values.dtype.kind == 'f' else "d"
        thresh = confusion_matrix.values.max() / 2.
        for i, j in np.ndindex(confusion_matrix.shape):
            plt.text(j, i, format(confusion_matrix.iloc[i, j], fmt),
                     horizontalalignment="center",
                     color="white" if confusion_matrix.iloc[i, j] > thresh else "black")

        plt.tight_layout()
        plt.ylabel(self.name1)
        plt.xlabel(self.name2)
        plt.show()