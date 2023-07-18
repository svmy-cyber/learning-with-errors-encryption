import os
from datetime import datetime
from time import perf_counter_ns
import json

# Utility variables
permitted_mod_values = (
    89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
    211,
    223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353,
    359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491,
    499,
    503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
    653,
    659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821,
    823,
    827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
    991,
    997)
noise_bound = 4  # constant


def generate_random_number(mod, non_zero=False):
    perf = perf_counter_ns()
    factor = 1
    for digit in str(perf):
        if int(digit) != 0:
            factor = (factor + int(digit)) * int(digit)
    factor = factor % mod
    if factor == 0 and non_zero == True:
        return 1
    return factor


# Load from File
def load_from_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    return content


# Save Key to File
def save_to_file(text, filename):
    with open(filename, 'w') as file:
        file.write(text)
    return filename


# Key Generation
def generate_public_key(vector_tuple, error_tuple, public_key_path):
    mod_value = len(error_tuple)
    vector_count = len(vector_tuple)
    equation_list = []
    for item_i in range(mod_value):
        eq = [[], error_tuple[item_i]]
        for vector_i in range(vector_count):  # populate the factors in the focus equation
            random_coefficient = generate_random_number(mod_value, True)
            eq[0].append(random_coefficient)
        result = 0
        for vector_i in range(vector_count):
            result += (vector_tuple[vector_i] * eq[0][vector_i])
        eq[1] += result
        equation_list.append(eq)
    nested_equation_list = [equation_list]
    equation_tuple = tuplify(nested_equation_list)[0]
    save_to_file(str(equation_tuple), public_key_path)


def tuplify(nested_equation_list):
    enclosing_list = []
    for equation_list in nested_equation_list:
        equation_list_nested_tuples = []
        for index, equation in enumerate(equation_list):
            nested_tuple = tuple(equation[0])
            parent_tuple = (nested_tuple, equation[1])
            equation_list_nested_tuples.append(parent_tuple)
        enclosing_list.append(tuple(equation_list_nested_tuples))
    return tuple(enclosing_list)


def generate_key_pair(mod_value_string, private_key_path, public_key_path):
    try:
        mod_value = int(mod_value_string)
    except ValueError:
        mod_value = 89
    if mod_value not in permitted_mod_values:
        mod_value = 89
    vector_count = mod_value // 23
    vector_list = []
    error_list = []
    for i in range(vector_count):  # populate private vector list
        random_vector = generate_random_number(mod_value, True)
        vector_list.append(random_vector)
    for item_i in range(mod_value):  # populate public_key (equation list)
        direction = generate_random_number(2)
        random_error = generate_random_number((noise_bound + 1))
        if direction == 0:
            random_error = random_error * -1
        error_list.append(random_error)
    error_tuple = tuple(error_list)
    vector_tuple = tuple(vector_list)
    save_to_file(str(vector_tuple), private_key_path)
    generate_public_key(vector_tuple, error_tuple, public_key_path)
    return private_key_path, public_key_path


def produce_equation_for_encapsulation(equation_tuple):
    mod_value = len(equation_tuple)
    equations_to_sum = mod_value // 23
    initial_equation_id = generate_random_number(mod_value)
    initial_equation = [list(equation_tuple[initial_equation_id][0]), equation_tuple[initial_equation_id][1]]
    vectors = initial_equation[0]
    result = initial_equation[1]
    for a in range(equations_to_sum):
        rand = generate_random_number(mod_value)
        equation_to_add = equation_tuple[rand]
        equation_to_add_vectors = equation_to_add[0]
        equation_to_add_result = equation_to_add[1]
        for index, vector in enumerate(equation_to_add_vectors):
            vectors[index] = vectors[index] + vector
        result = result + equation_to_add_result
    final_result_equation = [vectors, result]
    return final_result_equation


# Encryption
def encrypt(public_key_string, text_to_encrypt):
    public_key_equation_tuple = eval(public_key_string)
    mod_value = len(public_key_equation_tuple)
    nested_equation_list = []
    for i in range(len(text_to_encrypt)):
        equation_list = []
        binary_value = bin(ord(text_to_encrypt[i]))[2:]
        for t in range(len(binary_value)):
            equation = produce_equation_for_encapsulation(public_key_equation_tuple)
            if binary_value[t] == "1":
                increment = mod_value // 2
                equation[1] = equation[1] + increment
            equation_list.append(equation)
        nested_equation_list.append(equation_list)
    nested_equation_tuple = tuplify(nested_equation_list)
    return nested_equation_tuple


# Decryption
def decrypt(public_key_string, private_key_string, cipher_text_string):
    private_key_tuple = eval(private_key_string)
    public_key_equation_tuple = eval(public_key_string)
    nested_equation_tuple = eval(cipher_text_string)
    decrypted_string = ""
    mod_value = len(public_key_equation_tuple)
    encapsulation_addition_count = mod_value // 23
    amplified_noise_factor = encapsulation_addition_count * noise_bound
    total_observable_noise = noise_bound + amplified_noise_factor
    affirmative = ((mod_value - 1) / 2)
    affirmative_lower_boundary = affirmative - total_observable_noise
    affirmative_upper_boundary = affirmative + total_observable_noise
    negative_lower_boundary = total_observable_noise * -1
    negative_upper_boundary = total_observable_noise
    vectors = private_key_tuple
    for equation_tuple_i in range(len(nested_equation_tuple)):
        equation_tuple = nested_equation_tuple[equation_tuple_i]
        binary_character = ""
        for equation_i in range(len(nested_equation_tuple[equation_tuple_i])):
            equation = equation_tuple[equation_i]
            equation_vectors = equation[0]
            equation_sum = equation[1]
            actual_solution = 0
            for index, equation_vector in enumerate(equation_vectors):
                actual_solution = actual_solution + (equation_vector * vectors[index])
            difference = abs(equation_sum - actual_solution)
            if negative_lower_boundary <= difference <= negative_upper_boundary:
                binary_character = binary_character + "0"
            elif affirmative_lower_boundary <= difference <= affirmative_upper_boundary:
                binary_character = binary_character + "1"
            else:
                raise Exception("Invalid value detected")
        binary_int = int(binary_character, 2)
        ascii_char = chr(binary_int)
        decrypted_string = decrypted_string + ascii_char
    return decrypted_string


# Encrypt using Public Key
def encrypt_with_public_key(public_key_path, save_to_path, text_to_encrypt):
    public_key_string = load_from_file(public_key_path)
    cipher_equation_tuple = encrypt(public_key_string, text_to_encrypt)
    saved_to_path = save_to_file(str(cipher_equation_tuple), save_to_path)
    return saved_to_path


# Decrypt using Private Key
def decrypt_with_private_key(public_key_path, private_key_path, cipher_text_path, save_to_path):
    public_key_string = load_from_file(public_key_path)
    private_key_string = load_from_file(private_key_path)
    cipher_text_string = load_from_file(cipher_text_path)
    decrypted_string = decrypt(public_key_string, private_key_string, cipher_text_string)
    save_to_file(decrypted_string, save_to_path)
    return decrypted_string


def show_menu():
    print("1. Configure New Key Pair")
    print("2. Encrypt Text")
    print("3. Decrypt Text")
    print("4. Exit")


def process_identifier(identifier, identifier_type, action):
    if len(identifier) == 0:
        if action == "to_be_created":
            identifier = datetime.now().strftime("%Y%m%d_%H%M%S")
        else:
            raise Exception("No identifier provided")
    identifier_converted = convert_identifier_to_path(identifier, identifier_type)
    if os.path.isfile(identifier_converted):
        if action == "to_be_created":
            if identifier_type == "decrypted_text":
                suffix = "_" + datetime.now().strftime("%Y%m%d_%H%M%S")
                identifier_converted = convert_identifier_to_path(identifier + suffix, identifier_type)
                return identifier_converted
            else:
                raise Exception("File already exists")
        elif action == "to_be_read":
            return identifier_converted
    else:
        if action == "to_be_created":
            return identifier_converted
        elif action == "to_be_read":
            raise Exception("File does not exist")


def convert_identifier_to_path(identifier, identifier_type):
    return os.getcwd() + "\\" + identifier_type + "_" + identifier + ".txt"


def handle_option(selected_option):
    if selected_option == 1:
        print("Configure Key Pair")
        specified_mod_value = input("Enter a prime number between 89 and 997: ")
        identifier_input = input("Enter a Key Pair identifier string: ")
        private_key_path = process_identifier(identifier_input, "private_key", "to_be_created")
        public_key_path = process_identifier(identifier_input, "public_key", "to_be_created")
        generated_key_string_pair_tuple = generate_key_pair(specified_mod_value, private_key_path, public_key_path)
        print("Private Key Generated: " + generated_key_string_pair_tuple[0])
        print("Public Key Generated: " + generated_key_string_pair_tuple[1])
    elif selected_option == 2:
        print("Encrypt Text")
        public_key_input = input("Enter the Public Key's identifier: ")
        public_key_path = process_identifier(public_key_input, "public_key", "to_be_read")
        encrypted_text_identifier_input = input("Enter an identifier string for the encrypted text: ")
        encrypted_text_path = process_identifier(encrypted_text_identifier_input, "encrypted_text", "to_be_created")
        text_to_encrypt = input("Enter the text to encrypt:")
        encrypt_with_public_key(public_key_path, encrypted_text_path, text_to_encrypt)
        print("Encrypted Text Generated: " + encrypted_text_path)
    elif selected_option == 3:
        print("Decrypt Text")
        public_key_input = input("Enter the Public Key's identifier: ")
        public_key_path = process_identifier(public_key_input, "public_key", "to_be_read")
        private_key_input = input("Enter the Private Key's identifier: ")
        private_key_path = process_identifier(private_key_input, "private_key", "to_be_read")
        encrypted_text_input = input("Enter the Encrypted Text's Identifier: ")
        encrypted_text_path = process_identifier(encrypted_text_input, "encrypted_text", "to_be_read")
        decrypted_text_path = process_identifier(encrypted_text_input, "decrypted_text", "to_be_created")
        decrypted_text = decrypt_with_private_key(public_key_path, private_key_path, encrypted_text_path,
                                                  decrypted_text_path)
        print("Decrypted Text Saved To: " + decrypted_text_path)
        print("Decrypted Text: " + decrypted_text)
    elif selected_option == 4:
        print("Exiting the program...")
        exit()
    else:
        print("Invalid option. Please try again.")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    while True:
        show_menu()
        user_input = input("Select an option: ")
        try:
            option = int(user_input)
            handle_option(option)
        except ValueError:
            print("Invalid input. Please enter a number.")
