# -*- coding: utf-8 -*-
import os
import sys
from matplotlib.ticker import MultipleLocator
import random
import configparser
import numpy as np
import pandas as pd
from keras.optimizers import SGD
from keras.models import Sequential
from keras.layers import Dense, Activation
from keras.layers.advanced_activations import LeakyReLU
from keras.layers import Dropout
from keras import backend as K
from util import Utility
import matplotlib.pyplot as plt
import pylab as pl
import random
from keras.optimizers import Adam
import time
from keras.utils import plot_model

OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['KERAS_BACKEND'] = 'theano'
K.set_image_data_format('channels_first')


class GAN:
    def __init__(self):
        self.util = Utility()
        # 读取config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(self.util.join_path(full_path, 'config.ini'))
        except FileExistsError as e:
            self.util.print_message(FAIL, 'File exists error: {}'.format(e))
            sys.exit(1)

        self.wait_time = float(config['Common']['wait_time'])
        self.result_dir = self.util.join_path(
            full_path, config['Common']['result_dir'])

        # 遗传算法设置值
        self.genom_length = int(config['Genetic']['genom_length'])
        self.gene_dir = self.util.join_path(
            full_path, config['Genetic']['gene_dir'])
        self.genes_path = self.util.join_path(
            self.gene_dir, config['Genetic']['gene_file'])
        self.ga_result_file = config['Genetic']['result_file']
        self.eval_place_list = config['Genetic']['html_eval_place'].split('@')

        # GAN设置值
        self.input_size = int(config['GAN']['input_size'])
        self.batch_size = int(config['GAN']['batch_size'])
        self.num_epoch = int(config['GAN']['num_epoch'])
        self.max_sig_num = int(config['GAN']['max_sig_num'])
        self.max_explore_codes_num = int(
            config['GAN']['max_explore_codes_num'])
        self.max_synthetic_num = int(config['GAN']['max_synthetic_num'])
        self.weight_dir = self.util.join_path(
            full_path, config['GAN']['weight_dir'])
        self.gen_weight_file = config['GAN']['generator_weight_file']
        self.dis_weight_file = config['GAN']['discriminator_weight_file']
        self.gan_result_file = config['GAN']['result_file']
        self.gan_vec_result_file = config['GAN']['vec_result_file']
        self.generator = None

        # 读取基因列表，缺失值不填充
        self.df_genes = pd.read_csv(
            self.genes_path, encoding='utf-8', delimiter="\t").fillna('')
        self.flt_size = len(self.df_genes) / 2.0

        # 训练权重路径
        self.weight_path = self.util.join_path(self.weight_dir,
                                               self.gen_weight_file.replace('*', str(self.num_epoch)))

    def generator_model(self):
        model = Sequential()
        model.add(Dense(input_dim=self.input_size,
                  kernel_initializer='glorot_uniform', units=500))
        model.add(LeakyReLU(0.2))
        model.add(Dropout(0.5))

        model.add(Dense(self.input_size*10, kernel_initializer='glorot_uniform'))
        model.add(LeakyReLU(0.2))
        model.add(Dropout(0.5))

        model.add(Dense(self.input_size*5, kernel_initializer='glorot_uniform'))
        model.add(LeakyReLU(0.2))
        model.add(Dropout(0.5))

        model.add(Dense(kernel_initializer='glorot_uniform', units=3))
        model.add(Activation('tanh'))
        model.summary()
        plot_model(model, to_file='model.png', show_shapes=True)
        return model

    def discriminator_model(self):
        model = Sequential()
        model.add(Dense(input_dim=self.genom_length,
                  kernel_initializer='glorot_uniform', units=50))
        model.add(LeakyReLU(0.2))

        model.add(Dense(self.genom_length*10,
                  kernel_initializer='glorot_uniform'))
        model.add(LeakyReLU(0.2))

        model.add(Dense(1, kernel_initializer='glorot_uniform'))

        model.add(Activation('sigmoid'))
        model.summary()
        plot_model(model, to_file='model1.png', show_shapes=True)
        return model

    # 训练GAN，生成注入代码
    def train(self, list_sigs):
        # Load train data (=GA result).
        X_train = []
        X_train = np.array(list_sigs)
        X_train = (X_train.astype(np.float32) - self.flt_size) / \
            self.flt_size   # 把序号都变成[-1,1]范围

        # Build discriminator.
        discriminator = self.discriminator_model()
        d_opt = Adam(lr=0.0002, beta_1=0.5)
        discriminator.compile(loss='binary_crossentropy',
                              optimizer=d_opt, metrics=['accuracy'])

        # Build generator and discriminator.固定判别器
        discriminator.trainable = False
        self.generator = self.generator_model()
        dcgan = Sequential([self.generator, discriminator])
        g_opt = Adam(lr=0.0002, beta_1=0.5)
        dcgan.compile(loss='binary_crossentropy', optimizer=g_opt)
        XX = []
        D_Loss_list = []
        G_Loss_list = []

        # Execute train.
        num_batches = int(len(X_train) / self.batch_size)
        lst_scripts = []
        for epoch in range(self.num_epoch):
            for batch in range(num_batches):
                # Create noise for inputting to generator.
                noise = np.array([np.random.uniform(-1, 1, self.input_size)
                                 for _ in range(self.batch_size)])

                # Generate new injection code using noise.
                generated_codes = self.generator.predict(noise, verbose=0)

                # Update weight of discriminator.
                image_batch = X_train[batch *
                                      self.batch_size:(batch + 1) * self.batch_size]
                X = image_batch
                y = [random.uniform(0.7, 1.2) for _ in range(self.batch_size)]
                d_loss = discriminator.train_on_batch(X, y)
                X = generated_codes
                y = [random.uniform(0.0, 0.3) for _ in range(self.batch_size)]
                d_loss = discriminator.train_on_batch(X, y)

                # Update weight of generator.
                noise = np.array([np.random.uniform(-1, 1, self.input_size)
                                 for _ in range(self.batch_size)])
                g_loss = dcgan.train_on_batch(noise, [1]*self.batch_size)

                # Build HTML syntax from generated codes.
                for generated_code in generated_codes:
                    lst_genom = []
                    for gene_num in generated_code:
                        gene_num = (gene_num * self.flt_size) + self.flt_size
                        gene_num = int(np.round(gene_num))   # 取整数
                        if gene_num == len(self.df_genes):
                            gene_num -= 1
                        lst_genom.append(int(gene_num))
                    str_html = self.util.transform_gene_num2str(
                        self.df_genes, lst_genom)
                    self.util.print_message(OK, 'Train GAN : epoch={}, batch={}, g_loss={}, d_loss={}, {},  {}'.
                                            format(epoch, batch, g_loss, d_loss[0], np.round((generated_code * self.flt_size) + self.flt_size), str_html))
                    lst_scripts.append([str_html])
            XX.append(epoch)
            G_Loss_list.append(g_loss)
            D_Loss_list.append(d_loss[0])

            # Save weights of network each epoch.
            if (epoch+1) % 10 == 0:
                self.generator.save_weights(self.util.join_path(
                    self.weight_dir, self.gen_weight_file.replace('*', str(epoch + 1))))
                discriminator.save_weights(self.util.join_path(
                    self.weight_dir, self.dis_weight_file.replace('*', str(epoch + 1))))

                fig = plt.figure(figsize=(8, 6))   # 开一个新窗口，设置大小，分辨率
                ax = fig.add_subplot(111)

                plt.plot(XX, G_Loss_list, '#3399ff', label=u'G_Loss')
                plt.plot(XX, D_Loss_list, '#ffd700', label=u'D_Loss')

                pl.legend(loc='upper right', frameon=True,
                          shadow=True, facecolor='#c4c4c4')  # 图例
                ax.yaxis.grid(linewidth=0.5, color='#8e8e8e', linestyle='--',)

                # pl.xlabel(u'epoch')
                # pl.ylabel(u'loss')
                plt.title("epoch--loss")
                plt.ion()
                plt.savefig('./pic-{}.png'.format(epoch + 1), dpi=1000)
                plt.pause(2)
                plt.close()

        return lst_scripts

    # Transform from generated codes to gene list.
    def transform_code2gene(self, generated_code):
        lst_genom = []
        for gene_num in generated_code:
            gene_num = (gene_num * self.flt_size) + self.flt_size
            gene_num = int(np.round(gene_num))
            if gene_num == len(self.df_genes):
                gene_num -= 1
            lst_genom.append(int(gene_num))
        return lst_genom

    # Mean of two vectors.
    def vector_mean(self, vector1, vector2):
        return (vector1 + vector2)/2

    # Main control.
    def main(self):
        # Define saving path.
        gan_save_path = self.util.join_path(
            self.result_dir, self.gan_result_file.replace('*', "2"))
        vec_save_path = self.util.join_path(
            self.result_dir, self.gan_vec_result_file.replace('*', "3"))

        # Start generating injection code.
        if os.path.exists(self.weight_path):
            # Load trained model.
            self.generator = self.generator_model()
            self.generator.load_weights('{}'.format(self.weight_path))

            # Explore the valid injection codes.
            valid_code_list = []
            result_list = []
            for idx in range(self.max_explore_codes_num):
                self.util.print_message(NOTE, '{}/{} Explore valid injection code.'.format(idx + 1,
                                                                                           self.max_explore_codes_num))
                # Generate injection codes.
                noise = np.array(
                    [np.random.uniform(-1, 1, self.input_size) for _ in range(1)])
                generated_codes = self.generator.predict(noise, verbose=0)
                str_html = self.util.transform_gene_num2str(
                    self.df_genes, self.transform_code2gene(generated_codes[0]))
                valid_code_list.append([str_html, noise])
                result_list.append([str_html])

            # Save generated injection codes.
            if os.path.exists(gan_save_path) is False:
                pd.DataFrame(result_list, columns=['injection_code']).to_csv(
                    gan_save_path, mode='w', header=True, index=False)
            else:
                pd.DataFrame(result_list).to_csv(
                    gan_save_path, mode='a', header=False, index=False)

            # Synthesize injection codes.合成
            vector_result_list = []
            for idx in range(self.max_synthetic_num):
                noise_idx1 = np.random.randint(0, len(valid_code_list))
                noise_idx2 = np.random.randint(0, len(valid_code_list))
                self.util.print_message(
                    NOTE, '{}/{} Synthesize injection codes.'.format(idx+1, self.max_synthetic_num))
                self.util.print_message(OK, 'Use two injection codes : ({}) + ({}).'.
                                        format(valid_code_list[noise_idx1][0], valid_code_list[noise_idx2][0]))

                # Generate injection codes.
                synthesized_noise = self.vector_mean(
                    valid_code_list[noise_idx1][1], valid_code_list[noise_idx2][1])
                generated_codes = self.generator.predict(
                    synthesized_noise, verbose=0)
                str_html = self.util.transform_gene_num2str(
                    self.df_genes, self.transform_code2gene(generated_codes[0]))

                # Save running script.
                vector_result_list.append(
                    [str_html, valid_code_list[noise_idx1][0], valid_code_list[noise_idx2][0]])

            # Save synthesized injection codes.
            if os.path.exists(vec_save_path) is False:
                pd.DataFrame(vector_result_list,
                             columns=['synthesized_code', 'origin_code1', 'origin_code2']).to_csv(vec_save_path, mode='w', header=True, index=False)
            else:
                pd.DataFrame(vector_result_list).to_csv(
                    vec_save_path, mode='a', header=False, index=False)
        else:
            # Load created individuals by Genetic Algorithm.
            sig_path = self.util.join_path(
                self.result_dir, self.ga_result_file.replace('*', "1"))
            df_temp = pd.read_csv(sig_path, encoding='utf-8').fillna('')
            df_sigs = df_temp[~df_temp.duplicated()]  # 去除重复值

            list_sigs = []
            # Extract genom list from ga result.
            for idx in range(len(df_sigs)):
                list_temp = df_sigs['sig_vector'].values[idx].replace(
                    '[', '').replace(']', '').split(',')
                list_sigs.append([int(s) for s in list_temp])

            # Generate individuals (=injection codes).
            lst_scripts = []
            target_sig_list = []
            for target_sig in list_sigs:
                self.util.print_message(
                    NOTE, 'Start generating injection codes using {}'.format(target_sig))
                target_sig_list.extend(
                    [target_sig for _ in range(self.max_sig_num)])
            lst_scripts.extend(self.train(target_sig_list))

            # Save generated injection codes.
            if os.path.exists(gan_save_path) is False:
                pd.DataFrame(lst_scripts, columns=['injection_code']).to_csv(
                    gan_save_path, mode='w', header=True, index=False)

            else:
                pd.DataFrame(lst_scripts).to_csv(
                    gan_save_path, mode='a', header=False, index=False)
                print("-----------------save done--------------")

        self.util.print_message(
            NOTE, 'Done generation of injection codes using Generative Adversarial Networks.')


if __name__ == "__main__":
    util = Utility()
    full_path = os.path.dirname(os.path.abspath(__file__))
    config = configparser.ConfigParser()
    try:
        config.read(util.join_path(full_path, 'config.ini'), encoding='UTF-8')
    except FileExistsError as e:
        util.print_message(FAIL, 'File exists error: {}'.format(e))
        sys.exit(1)
    start = time.clock()

    gan = GAN()
    gan.main()
    end = time.clock()
    gan.main()

    print("----DONE!----")
    print("-----GAN生成总运行时间是：%0.3f\n------" % (end-start))
