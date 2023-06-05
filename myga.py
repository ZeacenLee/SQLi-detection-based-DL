# -*- coding: utf-8 -*-
from fileinput import close
import os
import sys
import random
import time
import configparser
import sqlparse
import pandas as pd
from decimal import Decimal
from util import Utility
import configparser
from util import Utility

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]

# Container of genes.


class Gene:
    genom_list = None
    evaluation = None

    def __init__(self, genom_list, evaluation):
        self.genom_list = genom_list
        self.evaluation = evaluation

    def getGenom(self):
        return self.genom_list

    def getEvaluation(self):
        return self.evaluation

    def setGenom(self, genom_list):
        self.genom_list = genom_list

    def setEvaluation(self, evaluation):
        self.evaluation = evaluation


# Genetic Algorithm.
class GeneticAlgorithm:
    def __init__(self):
        self.util = Utility()
        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(self.util.join_path(
                full_path, 'config.ini'), encoding='UTF-8')
        except FileExistsError as e:
            self.util.print_message(FAIL, 'File exists error: {}'.format(e))
            sys.exit(1)
        # Common setting value.
        self.wait_time = float(config['Common']['wait_time'])
        self.result_dir = self.util.join_path(
            full_path, config['Common']['result_dir'])
        # Genetic Algorithm setting value.
        self.genom_length = int(config['Genetic']['genom_length'])
        self.max_genom_list = int(config['Genetic']['max_genom_list'])
        self.select_genom = int(config['Genetic']['select_genom'])
        self.individual_mutation_rate = float(
            config['Genetic']['individual_mutation_rate'])
        self.genom_mutation_rate = float(
            config['Genetic']['genom_mutation_rate'])
        self.max_generation = int(config['Genetic']['max_generation'])
        self.max_fitness = int(config['Genetic']['max_fitness'])
        self.gene_dir = self.util.join_path(
            full_path, config['Genetic']['gene_dir'])
        self.genes_path = self.util.join_path(
            self.gene_dir, config['Genetic']['gene_file'])
        self.result_file = config['Genetic']['result_file']
        self.result_list = []
        self.lst_token = ('Token.Keyword.DML', 'Token.Name', 'Token.Keyword.DDL', 'Token.Keyword', 'Token.Wildcard', 'Token.Keyword.TZCast',
                          'Token.Punctuation', 'Token.Command', 'Token.Operator.Comparison', 'Token.Error')
        self.eva_score = 6

    # Create population.
    def create_genom(self, df_gene):
        lst_gene = []
        # for _ in range(self.genom_length):
        #     lst_gene.append(random.randint(0, len(df_gene.index)-1))
        lst_gene.append(random.randint(0, 20))
        lst_gene.append(random.randint(21, 64))
        lst_gene.append(random.randint(65, len(df_gene.index)-1))

        self.util.print_message(
            OK, 'Created individual : {}.'.format(lst_gene))
        return Gene(lst_gene, 0)

    # Evaluation.
    def evaluation(self, obj_ga, df_gene):
        # Build html syntax.
        indivisual = self.util.transform_gene_num2str(
            df_gene, obj_ga.genom_list)
        a = 0
        try:
            parsed = sqlparse.parse(indivisual)
            if len(parsed) == 1:
                stmt = parsed[0]
                for token in stmt.tokens:
                    # print(token.ttype)
                    for i in self.lst_token:
                        if i == str(token.ttype):
                            a += 1
                        else:
                            continue
                    # print("\n 评分是：{}".format(a))
        except sqlparse.exceptions.SQLParseError:
            print("Bad statement. Ignoring.\n'%s'" % indivisual)
        if a > self.eva_score:
            self.result_list.append([obj_ga.genom_list, indivisual])
        # Output evaluation results.
            self.util.print_message(OK, 'Individual="{} ({})", ''Score={}'.format(
                indivisual, obj_ga.genom_list, str(a)))
        return a

    # Select elite individual.
    def select(self, obj_ga, elite):
        # Sort in desc order of evaluation.
        sort_result = sorted(obj_ga, reverse=True, key=lambda u: u.evaluation)

        # Extract elite individuals.
        return [sort_result.pop(0) for _ in range(elite)]

    # Crossover (create offspring).
    def crossover(self, ga_first, ga_second):
        genom_list = []

        # Setting of two-point crossover.
        # cross_first = random.randint(0, self.genom_length)
        # cross_second = random.randint(cross_first, self.genom_length)
        one = ga_first.getGenom()
        second = ga_second.getGenom()

        # Crossover.
        # progeny_one = one[:cross_first] + \
        #     second[cross_first:cross_second] + one[cross_second:]
        # progeny_second = second[:cross_first] + \
        #     one[cross_first:cross_second] + second[cross_second:]
        progeny_one = one[:1]+second[1:2]+one[2:]
        progeny_second = second[:1]+one[1:2]+second[2:]
        genom_list.append(Gene(progeny_one, 0))
        genom_list.append(Gene(progeny_second, 0))

        return genom_list

    # Create population of next generation.
    def next_generation_gene_create(self, ga, ga_elite, ga_progeny):
        # Sort in asc order of evaluation.
        next_generation_geno = sorted(
            ga, reverse=False, key=lambda u: u.evaluation)

        # Remove sum of adding the elite group and offspring group.
        for _ in range(0, len(ga_elite) + len(ga_progeny)):
            next_generation_geno.pop(0)

        # Add the elite group and offspring group to the next generation.
        next_generation_geno.extend(ga_elite)
        next_generation_geno.extend(ga_progeny)
        return next_generation_geno

    # Mutation.
    def mutation(self, obj_ga, individual_mutation, genom_mutation, df_genes):
        lst_ga = []
        for idx in obj_ga:
            # Mutation to individuals.
            if individual_mutation > (random.randint(0, 100) / Decimal(100)):
                lst_gene = []
                for idx2 in idx.getGenom():
                    # Mutation to genes.
                    if genom_mutation > (random.randint(0, 100) / Decimal(100)):
                        lst_gene.append(random.randint(
                            0, len(df_genes.index)-1))
                    else:
                        lst_gene.append(idx2)
                idx.setGenom(lst_gene)
                lst_ga.append(idx)
            else:
                lst_ga.append(idx)
        return lst_ga

    # Main control.
    def main(self):
        # Load gene list.
        df_genes = pd.read_csv(
            self.genes_path, encoding='utf-8', delimiter="\t").fillna('')

        # Create saving file (only header).
        save_path = self.util.join_path(
            self.result_dir, self.result_file.replace('*', '1'))
        if os.path.exists(save_path) is False:
            pd.DataFrame([], columns=['sig_vector', 'sig_string']).to_csv(
                save_path, mode='a', header=False, index=False)

        # Evaluate indivisual each evaluating place in html.
        # Generate 1st generation.
        self.util.print_message(NOTE, '-----Create population.-----')
        current_generation = []
        for _ in range(self.max_genom_list):
            current_generation.append(self.create_genom(df_genes))

        # Evaluate each generation.
        for int_count in range(1, self.max_generation + 1):
            self.util.print_message(
                NOTE, '-----Evaluate : {}/{} generation.-----'.format(str(int_count), self.max_generation))

            for indivisual, idx in enumerate(range(self.max_genom_list)):
                self.util.print_message(OK, 'Evaluation individual : {}/{} in {} generation'.format(indivisual + 1,
                                                                                                    self.max_genom_list,
                                                                                                    str(int_count)))
                evaluation_result = self.evaluation(
                    current_generation[indivisual], df_genes)

                idx += 1

                current_generation[indivisual].setEvaluation(evaluation_result)
                time.sleep(self.wait_time)

            # Select elite's individual.选择好的个体
            elite_genes = self.select(current_generation, self.select_genom)

            # Crossover of elite gene.好的基因交叉
            progeny_gene = []
            for i in range(0, self.select_genom):
                progeny_gene.extend(self.crossover(
                    elite_genes[i - 1], elite_genes[i]))

            # Select elite group.
            next_generation_individual_group = self.next_generation_gene_create(
                current_generation, elite_genes, progeny_gene)

            # Mutation
            next_generation_individual_group = self.mutation(next_generation_individual_group,
                                                             self.individual_mutation_rate,
                                                             self.genom_mutation_rate,
                                                             df_genes)

            # Finish evolution computing for current generation.

            fits = [_.getEvaluation() for _ in current_generation]

            # evaluate evolution result.
            flt_avg = sum(fits) / float(len(fits))

            self.util.print_message(NOTE, '{} generation result: Min={}, Max={}, Avg={}.'.format(
                int_count, min(fits), max(fits), flt_avg))

            # Judge fitness.
            if flt_avg > self.max_fitness:
                self.util.print_message(
                    NOTE, 'Finish evolution: average={}'.format(str(flt_avg)))
                continue

            # Replace current generation and next generation.
            current_generation = next_generation_individual_group

        # Save individuals.
        pd.DataFrame(self.result_list, columns=['sig_vector', 'sig_string']).to_csv(save_path,
                                                                                    mode='a', header=True, index=False)

        # 删除重复值
        frame = pd.read_csv(save_path)
        self.result_list = frame.drop_duplicates()
        self.result_list.to_csv(save_path, encoding='utf8', index=False)

        # Output final result.
        str_best_individual = ''
        for gene_num in elite_genes[0].getGenom():
            str_best_individual += str(df_genes.loc[gene_num].values[0])
        str_best_individual = str_best_individual.replace(
            '%s', ' ').replace('&quot;', '"').replace('%comma', ',')
        self.util.print_message(
            NOTE, 'Best individual : "{}"'.format(str_best_individual))
        self.util.print_message(
            NOTE, 'Done creation of injection codes using Genetic Algorithm.')

        return self.result_list


if __name__ == "__main__":
    util = Utility()
    # Read config.ini.
    full_path = os.path.dirname(os.path.abspath(__file__))
    config = configparser.ConfigParser()
    try:
        config.read(util.join_path(full_path, 'config.ini'), encoding='UTF-8')
    except FileExistsError as e:
        util.print_message(FAIL, 'File exists error: {}'.format(e))
        sys.exit(1)

    # Genetic Algorithm setting value.
    max_try_num = int(config['Genetic']['max_try_num'])

    # Create a few individuals from gene list.
    for idx in range(max_try_num):
        util.print_message(
            NOTE, '{}/{} Create individuals using Genetic Algorithm.'.format(idx + 1, max_try_num))
        ga = GeneticAlgorithm()
        individual_list = ga.main()
