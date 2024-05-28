import numpy as np 
import pandas as pd 
from sklearn.metrics.pairwise import cosine_similarity
from tabulate import tabulate 
import json 

class Matrix: 
    
    def __init__(self, matrix:np.matrix, row_labels:list, col_labels:list, auto_gen_sim_matrix:bool=False, table_headers:list[str]=['Label 1', 'Label 2']):
        self.matrix = matrix 
        self.row_labels = row_labels
        self.col_labels = col_labels
        
        if auto_gen_sim_matrix: self.generate_similarity_matrix()
        else: 
            self.similarity_matrix = None
            self.most_similar_table_pretty = ""
            self.most_similar_table = None
            self.table_headers = table_headers
            
    def generate_similarity_matrix(self, ) -> None: 
        ''' Generates the similarity matrix using cosine similarity for this Matrix. '''
        
        self.similarity_matrix = cosine_similarity(np.asarray(self.matrix))
        
        print('generated similarity matrix') 
        print(self.similarity_matrix) 
        
        self.generate_similarity_table()
    
    
    def generate_similarity_table(self):
        
        if not self.similarity_matrix.any(): 
            if gen_sim_matrix: self.generate_similarity_matrix()
            else: 
                raise AttributeError('Matrix does not have a similarity matrix and [gen_sim_matrix] is set to False.')
        
        most_similar = []
        
        for i in range(self.similarity_matrix.shape[0]):
            self.similarity_matrix[i, i] = -1                                 # Exclude the self-similarity by setting it to a very low value
            most_similar_row_index = np.argmax(self.similarity_matrix[i])     # Find the index of the most similar row
            most_similar.append(most_similar_row_index)
            
        # Construct the table for most similar rows 
        table_results:list[tuple] = []
        for i, row in enumerate(most_similar):
            
            # Convert the row and cols to their labels
            label1 = self.row_labels[i]
            label2 = self.col_labels[row] 
            rating:float = round(self.similarity_matrix[i][row], 2)
            
            table_results.append((label1, label2, rating))

        # Alphabetize the table results 
        alphabetical_table_results:list[tuple] = sorted(table_results, key=lambda x: x[0])
        
        # Save result in self.most_similar_table
        self.most_similar_table = alphabetical_table_results
        self.most_similar_table_pretty = tabulate(alphabetical_table_results, headers=self.table_headers)


    def save(self, filename:str, dir:str='data/analysis-outcomes/', save_matrix:bool=False, save_similarity_matrix:bool=False, save_table:bool=False) -> None: 
        
        # Save the matrix
        if save_matrix: 
            np.savetxt(dir + filename + '.csv.', self.matrix.astype(int), delimiter=",", fmt="%d")
        
        # Save the similarity matrix 
        if self.similarity_matrix.any() and save_similarity_matrix: 
            np.savetxt(dir + filename + '-similarities-matrix' + '.csv', self.similarity_matrix.astype(int), delimiter=',', fmt="%d")
        
        if save_matrix or (self.similarity_matrix.any() and save_similarity_matrix): 
            # Save the rows and columns in a JSON
            row_col_dict:dict[str, list] = {
                'rows': self.row_labels,
                'cols': self.col_labels
            }
            
            with open(dir + filename + 'labels' + '.json', 'w+') as file: 
                json.dump(row_col_dict, file, indent=4)
        
        # Save the similarity table
        print(self.most_similar_table)
        
        if self.most_similar_table and save_table: 
            print('saving table')
            df:pd.DataFrame = pd.DataFrame(self.most_similar_table, columns=['Actor 1', 'Actor 2', 'Similarity Rating'])
            df.to_csv(dir + filename + '-most-similar-table' + '.csv', index=False)
            
        
        
        
        
    @staticmethod
    def create_blank_matrix(row_labels:list, col_labels:list) -> object:
        ''' Creates a blank Matrix object with the row labels and column labels supplied. 
        
            Args: 
                row_labels (list): list containing the row labels for this matrix
                col_labels (list): list containing the column labels for this matrix
                
            Returns: 
                Matrix: a Matrix object
        '''
        
        M:int = len(col_labels)     # Num rows
        N:int = len(row_labels)     # Num columns
        
        return Matrix(np.matrix(np.zeros(M,N)), row_labels, col_labels)
    
    