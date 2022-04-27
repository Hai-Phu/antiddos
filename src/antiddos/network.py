import numpy as np
import pickle

class MLP_Network:
    def __init__(self, layers, weight_file):
		# Mô hình layer ví dụ [2,2,1]
      #load weight
      with open(weight_file, 'rb') as file:
        weight = pickle.load(file)

      self.layers = layers 

      # Tham số W, b
      self.W = []
      self.b = []
      
      # Khởi tạo các tham số ở mỗi layer
      for i in range(0, len(layers)):
        self.W.append(weight[i*2])
        self.b.append(weight[i*2+1])

    def get_weight(self):
      return self.W

    def relu(self, x):
      return np.maximum(x, 0)
      
    def predict(self, X):
      for i in range(0, len(self.layers)):
        if i < len(self.layers) - 1:
          X = self.relu(np.dot(X, self.W[i]) + (self.b[i].T))
        else:
          X = np.argmax(np.dot(X, self.W[i]) + (self.b[i].T))
      return X