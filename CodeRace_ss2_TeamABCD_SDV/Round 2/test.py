import src.applications as app
import src.lib

#Exploiting Eval()7
# ex_eval = '__import__("os").system("echo FALIED: boschcoderace_sum_of_list_number")'
# app.boschcoderace_sum_of_list_number(ex_eval)

# print(app.boschcoderace_random())

string_test = "127.0.0.1"
print(app.boschcoderace_validate_ip(string_test))