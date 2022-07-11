import numpy as np
import pickle

class MLP_Network:
    def __init__(self, layers, weight_file):
		# Mô hình layer ví dụ [2,2,1]
      #load weight

      min_max_weight = np.load(weight_file,allow_pickle=True)
      self.layers = layers 

      # Tham số W, b
      self.W = []
      self.b = []
      self.x_min = min_max_weight['xmin']
      self.x_max = min_max_weight['xmax']
      weight = min_max_weight['weights']
      # Khởi tạo các tham số ở mỗi layer
      for i in range(0, len(layers)):
        self.W.append(weight[i*2])
        self.b.append(weight[i*2+1])

    def get_weight(self):
      return self.W

    def relu(self, x):
      return np.maximum(x, 0)

    def softmax(self, x):
        f_x = np.exp(x) / np.sum(np.exp(x))
        return f_x

    def predict(self, X):
      X = (X-self.x_min)/(self.x_max-self.x_min)
      for i in range(0, len(self.layers)):
        if i < len(self.layers) - 1:
          X = self.relu(np.dot(X, self.W[i]) + (self.b[i].T))
        else:
          X = np.argmax(self.softmax(np.dot(X, self.W[i]) + (self.b[i].T)),axis=1)
      return X