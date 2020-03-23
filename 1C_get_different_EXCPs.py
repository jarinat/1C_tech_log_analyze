#! python3
import os, re
import sys
import argparse

def get_args():
    
    parser = argparse.ArgumentParser(description = 'Группировка событий журанала регистрации')

    parser.add_argument(
        '--log_path',
        type=str,
        default=os.getcwd(),
        help='Каталог ресположения тех.журнала, в котором находится\
            подкаталоги rphost_XXXX, ragent_XXXX и т.п.\
            По умолчанию - текущий рабочий каталог.')


    parser.add_argument(
        '--log_file_path_reg_exp',
        type=str,
        default='[\\\/]rphost_\d+[\\\/]\d{8}.log',
        help='Регулярное выражение, по которому проверяется имя и расположение файла лога.\
            По-умолчанию анализируются все файлы .log в каталогах rphost_XXXX')


    return parser.parse_args()

args = get_args()

log_path = args.log_path
log_file_path_regex = args.log_file_path_reg_exp


result = {}


not_interested_event_regex = re.compile(r'''
    (
    # Исключения, связанные с принудительным завершением работы сессий:
    Сеанс\sотсутствует\sили\sудален|
    Текущему\sсоединению\sс\sинформационной\sбазой\sне\sназначен\sсеанс|
    Session\sis\snot\savailable\sor\shas\sbeen\sdropped|
    Сеанс\sработы\sзавершен\sадминистратором|
    Соединение\sс\sсервером\sбаз\sданных\sразорвано\sадминистратором|
    Требуется\sпереустановка\sсоединения|
    The\sdatabase\sserver\sconnection\sis\sclosed\sby\sthe\sadministrator|
    Connection\sreinstall\sis\srequired|
    No\ssession\sassigned\sto\sthe\scurrent\sinfobase\sconnection|
    Session\sclosed\sby\sadministrator|

    # Возможность доступа в ИБ
    Начало\sсеанса\sс\sинформационной\sбазой\sзапрещено|
                                        
    # Исключения при попытке входа в ИБ
    Неправильное\sимя\sпользователя\sили\sпароль|
    Incorrect\suser\sname\sor\spassword|
    Invalid\suser\sname\sor\spassword|
    Неправильное\sимя\sили\sпароль\sпользователя|
                                        
    # Исключения, связанные с сетью:
    Ping\stime\sout\sexpired\son\sdirection:\sdirectionID|
    An\sexisting\sconnection\swas\sforcibly\sclosed\sby\sthe\sremote\shost|
    The\ssemaphore\stimeout\speriod\shas\sexpired|

    # Исключения связанные с остановкой рабочих процессов:
    Stopping\sthe\sprocess\.\sOutgoing\scalls\sare\snot\sallowed|
    Work\sprocess\snot\sfound|
    OnFinishRpHost|
    onFinishConnection|
	Процесс\sзавершается\.\sИсходящий\sвызов\sзапрещен\.|

    # В данных исключения не нашел полезной информации:
    HTTP:\sBad\srequest\nОшибка\sпри\sвыполнении\sзапроса\sGET\sк\sресурсу\s/e1cib/getURLPictureManifest:\'|
    HTTP:\sBad\srequest\nError\sexecuting\sthe\squery\sGET\sto\sresource\s/e1cib/getURLPictureManifest:\'|
    HTTP:\sNot\sfound\nОшибка\sпри\sвыполнении\sзапроса\sGET\sк\sресурсу\s/e1cib/modules/srcLine:\'|
    HTTP:\sNot\sfound\nError\sexecuting\sthe\squery\sGET\sto\sresource\s/e1cib/modules/srcLine:\'
    )''', re.VERBOSE)


analyze_event_regex = re.compile(r''',EXCP,.*,
                                Exception=([-a-zA-Z0-9]+),
                                Descr=([\'"])
                                (?:src\\[\w\d\.\\/]+\(\d+\):\n)?       # для подобных вещей src\VResourceInfoBaseImpl.cpp(1069):
                                (?:\1: )?                           # иногда перед описанием события повторяется идентификатор Exception
                                (?:\1)?                           # иногда перед описанием события повторяется идентификатор Exception
                                (((
                                (?!\2)                              # не должно быть ковычек
                                (?!(ID=[-\w\d]{36}))                # и ID=...
                                (?!(HRESULT=[\w\d]+,))                # и HRESULT=...
                                )(.|\n))*)
                                (\2|                                # Descr берем до следующих кавычек \2
                                ID=[-\w\d]{36}|                     # либо до поля ID=
                                HRESULT=[\w\d]+,)                     # либо до поля HRESULT=
                                ''', re.VERBOSE)



def analyze_event(event):
    
    # 0. Пропускаем не интересные события:
    if not_interested_event_regex.search(event) is not None:
        return
    
    # 1. Первый этап анализа события
    analyze_event_result = analyze_event_regex.search(event)
    if analyze_event_result is None:
        return

    # 2. Часть описание отсекли на этапе 1
    descr = analyze_event_result.group(3)
    descr = re.sub(r'tt\d{2,3}', 'tt00', descr) # имена временных таблиц
    descr = re.sub(r'0x[\w\d]{32}', '0x00000000000000000000000000000000', descr) # идентификаторы объектов
    descr = re.sub(r'ID \d{1,4}', 'ID 00', descr) # ID 00
    descr = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?', '000.000.000.000', descr) # IP-адреса
    descr = re.sub(r'(к ресурсу|to resource) [\d\w/]+', r'\1 XXX', descr)
    descr = re.sub(r'( GET | POST )', ' XXX ', descr)
    descr = re.sub(r'ref=[\w\d]{32}', 'ref=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', descr)
    descr = re.sub(r'line=\d+ file=src', 'line=0000 file=src', descr)
    descr = re.sub(r': \{\(\d+, \d+\)\}:', ': {(00, 00)}:', descr)
    

    
    excp_id = analyze_event_result.group(1)  + ' : ' + descr # analyze_event_result.group(3)
    
    if not excp_id in result:
        result[excp_id] = 0

    result[excp_id] = result[excp_id] + 1
    
        
first_event_line_regex = re.compile(r'^\d\d:\d\d.\d+')


def read_file(file_path):
    current_file = open(file_path, encoding="utf8")
    cur_line = current_file.readline()
    full_line = ''
    while cur_line:
        
        if first_event_line_regex.search(cur_line) is not None:
            if full_line != '':
                analyze_event(full_line)
                
            full_line = cur_line
        else:
            full_line = full_line + cur_line
            
        cur_line = current_file.readline()
    analyze_event(full_line)


def print_sorted_dict(unsorted_dict):
    list_dict = list(unsorted_dict.items())
    list_dict.sort(key = lambda i: -i[1])

    for i in list_dict:
        print(i[0], ':', i[1], '\n-------------------------------------------------------------')

folder = []


for i in os.walk(log_path):
    folder.append(i)

	
log_file_path_regex = re.compile(r'%s' % log_file_path_regex)
for address, dirs, files in folder:
    for file in files:
        file_path = os.path.join(address, file)
        if log_file_path_regex.search(file_path) is not None:
            read_file(file_path)



print('-----------------------------------------------------------------------------------',
   '\n|                                                                                   |',
   '\n|                                     NEW ANALYZE                                   |',
   '\n|                                                                                   |',
    '\n-----------------------------------------------------------------------------------')
print(' События, содержащие следующий тескст исключены из анализа:\n',
      not_interested_event_regex.pattern,
      '\n-------------------------------- НАЧАЛО АНАЛИЗА ----------------------------------\n')

print_sorted_dict(result)

