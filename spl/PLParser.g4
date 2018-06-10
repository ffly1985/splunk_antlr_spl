grammar PLParser;
//import PLLexer;
//options { tokenVocab=PLLexer; }

prog : stat+;

//stat: expr NEWLINE          # printExpr
//    | ID '=' expr NEWLINE   # assign
//    | NEWLINE               # blank
//    ;
/*
    一个完整的Spl语句
*/
stat: pipe_spl_fragment;

ID : Letter+LetterOrDigit* ;
INT : [0-9]+ ;
NUMBER : Digits ('.' Digits?)?
           |  '.' Digits
           ;
NEWLINE:'\r'? '\n' ;
STRING : '"'('""'|~'"')* '"' ;
WC_STRING : ('*' | STRING)* ;
//字段列表
id_list : ID (','ID)*;
field : ID ;
field_list : ID (',' ID)* ;
wc_field : (ID | '*' )+ ;
wc_field_list : wc_field (','wc_field)* ;

/*
    跳过空白字符
*/
WS : [ \t]+ -> skip;
//赋值
//ASSIGN: '=';


fragment LetterOrDigit
    : Letter
    | [0-9]
    ;

fragment Letter
    : [a-zA-Z$_] // these are the "java letters" below 0x7F
    //| ~[\u0000-\u007F\uD800-\uDBFF] // covers all characters above 0x7F which are not a surrogate
    //| [\uD800-\uDBFF] [\uDC00-\uDFFF] // covers UTF-16 surrogate pairs encodings for U+10000 to U+10FFFF
    ;
fragment Digits
    : [0-9]+
    ;

bool
    : 'true' | 'false'
    ;
/*
    数学运算符
*/
MUL:                                '*';
ADD:                                '+';
MINUSMINUS:                          '--';
SUB:                               '-';
DIV:                                 '/';
MOD:                                 '%';

/*
    比较运算符
*/
EQ:                                  '=';
NEQ:                                 '!=';
LESS:                                '<';
LESS_EQ:                             '=<';
GREATER:                             '>';
GREATER_EQ:                          '>=';

comparisonOperator
    : EQ | NEQ | LESS | LESS_EQ | GREATER | GREATER_EQ
    ;

//统计函数
/*AVG:                                 'avg';
BIT_AND:                             'bit_and';
BIT_OR:                              'bit_or';
BIT_XOR:                             'bit_xor';
COUNT:                               'count';
GROUP_CONCAT:                        'group_concat';
MAX:                                 'max';
MIN:                                 'min';
STD:                                 'std';
STDDEV:                              'stddev';
STDDEV_POP:                          'stddev_pop';
STDDEV_SAMP:                         'stddev_samp';
SUM:                                 'sum';
VAR_POP:                             'var_pop';
VAR_SAMP:                            'var_samp';
VARIANCE:                            'variance';

stats_agg_name
    : AVG
    | COUNT
    | SUM
    | MAX
    | MIN
    | SUM
    | STD
    | STDDEV
    | STDDEV_POP
    | STDDEV_SAMP
    | VAR_POP
    | VAR_SAMP
    | VARIANCE
    ;
*/
stats_agg_name
    : 'avg'
     | 'count'
     | 'sum'
     | 'max'
     | 'min'
     | 'sum'
     | 'std'
     | 'stddev'
     | 'stddev_pop'
     | 'stddev_samp'
     | 'var_pop'
     | 'var_samp'
     | 'variance'
    ;
stats_agg_term
    :stats_agg_name ('(' (field | math_expr) ')')?
    ;
/*
*/
primitive_expr
    : functionCall
    | field
    | INT
    | STRING
    ;

functionCall
    : functionName'(' functionParamList ')';

functionName
    : ID;

functionParamList
    : functionParam (','functionParam)* ;

functionParam
    : field
    | INT
    | STRING
    | math_expr
    ;
/*
    数学运算表达式，使用eval函数来计算
*/
math_expr: math_expr op=('*'|'/') math_expr
    | math_expr op=('+'|'-') math_expr
    | primitive_expr
    | '(' math_expr ')'
    ;

/*
    条件运算表达式:
        1、字段与数字比较
        2、字段与字符串
        3、字段与数学表达式
        4、数学表达式与数学表达式

*/
compare_expr
    : field
    | functionCall
    | INT
    | STRING
    | math_expr comparisonOperator math_expr
    | '(' compare_expr ')'
    ;

//cond_expr_index: 'index=' | ;
/*
    逻辑运算表达式
*/
logical_expr
    : NOT logical_expr
    | logical_expr logicalOperator logical_expr
    | '(' logical_expr ')'
    | compare_expr
    ;
/*
    通用表达式，包含函数、数学运算、条件运算、逻辑运算
*/
eval_expr
    : primitive_expr
    | math_expr
    | compare_expr
    | logical_expr
    ;

//赋值表达式
assign_expr
    : ID EQ eval_expr
    ;

//SPL语句定义开始
/*
    SPL语句定义
*/
pipe_spl_fragment
    :(pipe_command_source|pipe_command_null) NEWLINE* (PIPE_SYMBOL NEWLINE* pipe_command)*
    ;
/*
    SPL 命令定义
*/
pipe_command_source
    : pipe_command_search /*splunk*/
    | pipe_command_null
    ;

pipe_command
    : pipe_command_source
     |pipe_command_abstract
     | pipe_command_accum
     | pipe_command_addcoltotals
     | pipe_command_addinfo
     | pipe_command_addtotals
     | pipe_command_analyzefields
     | pipe_command_anomalies
     | pipe_command_anomalousvalue
     | pipe_command_anomalydetection
     | pipe_command_append
     | pipe_command_appendcols
     | pipe_command_appendpipe
     //| pipe_command_arules
     //| pipe_command_associate
     //| pipe_command_audit
     | pipe_command_autoregress
     | pipe_command_bin
     //| pipe_command_bucketdir
     | pipe_command_chart
     | pipe_command_cluster
     | pipe_command_cofilter
     | pipe_command_collect
     | pipe_command_concurrency
     | pipe_command_contingency
     | pipe_command_convert
     | pipe_command_correlate
     | pipe_command_datamodel
     | pipe_command_dbinspect
     | pipe_command_dedup
     | pipe_command_delete
     | pipe_command_delta
     | pipe_command_diff
     | pipe_command_erex
     | pipe_command_eval
     | pipe_command_eventcount
     | pipe_command_eventstats
     | pipe_command_extract
     | pipe_command_fieldformat
     | pipe_command_fields
     | pipe_command_fieldsummary
     | pipe_command_filldown
     | pipe_command_fillnull
     | pipe_command_findtypes
     | pipe_command_folderize
     | pipe_command_foreach
     | pipe_command_format
     | pipe_command_from
     | pipe_command_gauge
     | pipe_command_gentimes
     | pipe_command_geom
     | pipe_command_geomfilter
     | pipe_command_geostats
     | pipe_command_head
     | pipe_command_highlight
     | pipe_command_history
     //| pipe_command_iconify
     | pipe_command_input
     | pipe_command_inputcsv
     | pipe_command_inputlookup
     | pipe_command_iplocation
     | pipe_command_join
     | pipe_command_kmeans
     | pipe_command_kvform
     | pipe_command_loadjob
     | pipe_command_localize
     | pipe_command_localop
     | pipe_command_lookup
     | pipe_command_makecontinuous
     | pipe_command_makemv
     | pipe_command_makeresults
     | pipe_command_map
     //| pipe_command_mcollect
     //| pipe_command_metadata
     //| pipe_command_metasearch
     //| pipe_command_meventcollect
     | pipe_command_mstats
     | pipe_command_multikv
     | pipe_command_multisearch
     | pipe_command_mvcombine
     | pipe_command_mvexpand
     | pipe_command_nomv
     | pipe_command_outlier
     | pipe_command_outputcsv
     | pipe_command_outputlookup
     | pipe_command_outputtext
     | pipe_command_overlap
     | pipe_command_pivot
     | pipe_command_predict
     | pipe_command_rangemap
     | pipe_command_rare
     | pipe_command_regex
     | pipe_command_relevancy
     | pipe_command_reltime
     | pipe_command_rename
     | pipe_command_replace
     | pipe_command_rest
     | pipe_command_return
     | pipe_command_reverse
     | pipe_command_rex
     | pipe_command_rtorder
     | pipe_command_savedsearch
     | pipe_command_script
     | pipe_command_scrub
     | pipe_command_search
     | pipe_command_searchtxn
     | pipe_command_selfjoin
     | pipe_command_sendemail
     | pipe_command_set
     | pipe_command_setfields
     | pipe_command_sichart
     | pipe_command_sirare
     | pipe_command_sistats
     | pipe_command_sitimechart
     | pipe_command_sitop
     | pipe_command_sort
     | pipe_command_spath
     | pipe_command_stats
     | pipe_command_strcat
     | pipe_command_streamstats
     | pipe_command_table
     | pipe_command_tags
     | pipe_command_tail
     | pipe_command_timechart
     | pipe_command_timewrap
     | pipe_command_top
     | pipe_command_transaction
     | pipe_command_transpose
     | pipe_command_trendline
     | pipe_command_tscollect
     | pipe_command_tstats
     | pipe_command_typeahead
     | pipe_command_typelearner
     | pipe_command_typer
     | pipe_command_union
     | pipe_command_uniq
     | pipe_command_untable
     | pipe_command_where
     | pipe_command_x11
     | pipe_command_xmlkv
     | pipe_command_xmlunescape
     | pipe_command_xpath
     | pipe_command_xyseries
    ;

/*
    abstract
    生成搜索结果文本的摘要、汇总或简单表示。原始文本由汇总代替。
    摘要由评分机制生成。即使事件大于选定的   maxlines，那些在相邻行上具有更多文本术语和术语的事件仍优先于术语
    较少的事件。如果某行包含⼀个搜索术语，则其邻近行也是部分匹配，并且可能会返回这些行，以提供上下文。当所
    选行之间存在间隙时，这些行带有省略号前缀  (...) 。
*/
pipe_command_abstract
    : 'abstract' ('maxterms' EQ INT |  'maxlines' EQ INT)*
    ;
/*
    对field为数值的所有事件，accum命令计算这些数字的累计值或总和。累计值既可以返回⾄同⼀个字段，也可
    以返回至指定的newfield。
    示例:
    ... | accum quantity AS total_quantity

*/
pipe_command_accum
    : 'accum' field (('AS' | 'as') field)?
    ;

/*
    addcoltotals命令
    将新的结果附加到搜索结果集的末尾。结果包含每个数字字段的总和，或者也可以指定要汇总哪
    些字段。结果显在"统计"选项卡中。若已指定了labelfield参数，则名称已指定的列将添加到统计结果表。
    示例:
    1、... | addcoltotals labelfield=change_name label=ALL
    2、
    3、
*/
pipe_command_addcoltotals
    : 'addcoltotals' ('labelfield' EQ field | 'label' EQ STRING)* field_list?
    ;
/*
    addinfo
    命令将新的结果附加到搜索结果集的末尾。结果包含每个数字字段的总和，或者也可以指定要汇总哪
    些字段。结果显在"统计"选项卡中。若已指定了labelfield参数，则名称已指定的列将添加到统计结果表。
*/
pipe_command_addinfo
    : 'addinfo'
    ;


/*
   addtotals待完善
*/
pipe_command_addtotals
    : 'addtotals' ('row' EQ bool) ('col' EQ bool) ('labelfield' EQ field)? ('label' EQ STRING)
      ('fieldname' EQ 'field')? field_list
    ;

/*
    analyzefields
    将  field  作为离散随机变量，此命令将分析所有数字字段来决定这些字段中的每⼀个字段   predict   classfield   值的能
    力。它将决定目标   classfield   中的值与其他字段中数字值之间关系的稳定性。
*/
pipe_command_analyzefields
    : 'analyzefields' 'classfield' EQ field
    ;

/*
    anomalies
    使用   anomalies   命令查找异常或意外的事件或字段。

    1、显⽰感兴趣的事件，忽略⿊名单  'boring events'  中的任何事件。以降序排列事件列表， unexpectedness  字段中
      的值最⾼者优先列出。
      ... | anomalies blacklist=boringevents | sort -unexpectedness

    2、与交易结合使⽤，以查找看起来有异常的时间区域。
      ... | transaction maxpause=2s | anomalies
    3、分别在每个数据来源中查找异常  --  在⼀个数据来源中的模式不会影响它在另⼀个数据来源中处于异常状态。
      ... | anomalies by source
*/
pipe_command_anomalies
    : 'anomalies'
       ('threshold' EQ NUMBER |  'labelonly' EQ bool | 'normalize' EQ bool |  'maxvalues' EQ INT
            | 'field' EQ field | 'blacklist' EQ filename=STRING |  'blacklistthreshold' EQ NUMBER)*
       column_split_by_clause?
    ;

/*
    anomalousvalue
    为所有事件的每个字段计算异常分数（相对于其他事件中此字段的值而言）。对于数值字段，
    它会根据出现频率或与平均值的标准偏差数来发现或汇总数据中的异常值。
    ⽰例
     1、仅返回搜索结果中不常⻅的值 ：仅返回搜索结果中不常⻅的值
        ... | anomalousvalue
        等价于
        ...| anomalousvalue action=filter pthresh=0.01
     2、返回来⾃主机 ：返回来自主机"reports"的非常见值
        host="reports" | anomalousvalue action=filter pthresh=0.02
     3、返回每个数值字段的异常统计信息的汇总。
        source=/var/log* | anomalousvalue action=summary pthresh=0.02 | search isNum=YES
*/
pipe_command_anomalousvalue
    : 'anomalousvalue'
        (av_options | 'action' EQ ('annotate' | 'filter' | 'summary') | 'pthresh' EQ NUMBER )*
        field_list
    ;

//
av_options
    : 'minsupcount' EQ INT
    | 'maxanofreq' EQ NUMBER
    | 'minsupfreq' EQ NUMBER
    | 'minnormfreq' EQ NUMBER
    ;

/*
    anomalydetection
    这是⼀种流式和报表命令，通过计算每个事件的概率并检测异常小的概率来识别异常事件。可能性定义为事件中每个
    独立字段值的频率之乘积。
    对于类别字段，值  X  的频率是指出现次数  X  除以总事件数。
    对于数字字段，⾸先会为所有值构建⼀个直方图，然后会计算值  X  的频率，即包含  X  的数据桶的大小除以总
    事件数。

    ... | anomalydetection action=summary
    ... | anomalydetection method=zscore action=filter pthresh=0.05
    ... | anomalydetection method=iqr action=tf param=4 uselower=true mark=true
    (未通过测试)
    method作为关键字冲突了
*/
pipe_command_anomalydetection
    : 'anomalydetection'
      (method_option | action_option | pthresh_option | cutoff_option)*
      field_list
    ;
method_option
    :  'method' EQ ('histogram' | 'zscore' | 'iqr')
    ;
action_option
    : 'action' EQ (action_option1 | action_option2)
    ;
//methord = histogram 或zscore时候的action
action_option1
    : 'filter' | 'annotate' | 'summary'
    ;
//method = iqr的action
action_option2
    : 'remove' | 'rm' | 'transform' | 'tf'
    ;
pthresh_option
    : 'pthresh' EQ NUMBER
    ;
cutoff_option
    : 'cutoff' EQ bool
    ;

/*
    append
    将子搜索结果附加到当前结果。append 命令仅对历史数据有效，若用于实时搜索则不会产生正确的结果。
*/
pipe_command_append
    : 'append' append_subsearch_options* subsearch
    ;

append_subsearch_options
    :'maxtime' EQ INT | 'maxout' EQ INT | 'timeout' EQ INT
    ;


/*
    appendcols
    将子搜索结果的字段附加到输人搜索结果中。以非下划线字符  ( _ )  开头的子搜索的外部字段不会计入当前结果。第
    ⼀个子搜索结果与第⼀个主结果合并，第⼆个子搜索结果与第二个主结果合并，依此类推。
*/
pipe_command_appendcols
    : 'appendcols'
        ('override' EQ  <bool> | append_subsearch_options)*
        subsearch
    ;

/*
    appendpipe
    将子管道所应用的结果附加到当前结果中。使用 appendpipe 命令附加转换命令的输出。当构建表格或图表时，此操作
    对于提供摘要或总计或者整个数据集的描述性行都很有用。或者当您需要原始结果进行其他计算的时候，此操作也可
    能有用。
*/

pipe_command_appendpipe
    : 'appendpipe' ('run_in_preview' EQ bool)? subpipeline
    ;
subpipeline
    : STRING
    ;

/*
    autoregress
    通过将  field  的⼀个或多个先前值复制到每个事件中，让这些事件为自动回归或移动平均值的计算做好准备。
    待完善
*/
pipe_command_autoregress
    : 'autoregress'
    ;

/*
   bin
   bucket命令的别名
   通过调整field值将连续数字值放入离散集合或数据桶，这样特定集合中的所有项目都具有同样的值。
   注意：chart 和 timechart 命令会调用  bin  命令。在实际场景中，bin命令用来处理chart 和 timechart 命令无法处理的统计
   运算。
   ... | bin _time span=5m | stats avg(thruput) by _time host
   ... | bin size bins=10 | stats count(_raw) by size
   ... | bin amount end=1000
*/
pipe_command_bin
    : 'bin' bin_options? field ('AS' field)?
    ;

bin_options
    : 'bins' EQ INT
    | 'span' EQ (log_span | time_span)
    | 'minspan' EQ time_span
    | start_end
    ;

log_span
    : INT? 'log' INT
    ;
time_span
    : INT time_scale?
    ;
/*
    时间单位,秒 分 小时 天 月 微秒 毫秒 百分之一秒 十分之一秒
*/
time_scale
    : second | minute | hr | day | month | subseconds
    ;
time_scale_all
    : second | minute | hr | day | month | subseconds | quarter | week | year
    ;

//亚秒
subseconds  : 'us' | 'ms' | 'cs' | 'ds';
//秒
second         : 's' | 'sec' | 'secs' | 'second' | 'seconds';
//分钟
minute         : 'm' | 'min' | 'mins' | 'minute' | 'minutes';
//小时
hr          : 'h' | 'hr' | 'hrs' | 'hour' | 'hours';
day         : 'd' | 'day' | 'days';
//周
week        : 'w' | ' week' | 'weeks';
//月
month       : 'mon' | 'month' | 'months';
//季度
quarter     : 'q' | 'qtr' | 'qtrs' | 'quarter' | 'quarters';
//年
year        : 'y' | 'yr' | 'yrs' | 'year' | 'years';


start_end
    : 'start' EQ INT
    | 'end' EQ INT
    ;
/*
    chart命令是一种转换命令，将结果以表格形式返回，之后可以使用返回的结果，以柱形图、折线图、面积图或饼图等图表显示数据。

     ... | chart max(delay) OVER foo
     ... | chart max(delay) OVER foo BY bar
     ... | chart eval(avg(size)/max(delay)) AS ratio BY host user
     ... | chart max(delay) BY size bins=10
     ... | chart avg(size) BY host
     ... | chart count BY date_mday span=3 date_hour span=12
     sourcetype=access_* | chart count(eval(method="GET")) AS GET, count(eval(method="POST")) AS POST by host
     sourcetype=access_* status=200 action=purchase | transaction clientip maxspan=10m | chart count BY duration
     span=log2
     已知问题
     1、'method' 冲突

*/
pipe_command_chart
    : 'chart' chart_option*
      ( stats_agg_term | sparkline_agg | 'eval' '(' eval_expr ')' )*
      ( 'BY'  row_split column_split  | 'OVER' row_split? ('BY' column_split)? )?
    ;

chart_option
    : 'cont' EQ bool | 'format' EQ STRING | 'limit' EQ INT | 'sep' EQ STRING
    ;

sparkline_agg
    : 'sparkline'  sparkline_agg_term (',' time_span)?
    ;

sparkline_agg_term
    : sparkline_func_name ('(' field ')')?
    ;

sparkline_func_name
    : 'c' | 'count' | 'dc' | 'mean' | 'avg' | 'stdev' | 'stdevp' | 'var' | 'varp' | 'sum' | 'sumsq' | 'min' | 'max' | 'range'
    ;
row_split
    : field bin_options*
    ;
tc_option
    :  bin_options | 'usenull' EQ bool | 'useother' EQ bool | 'nullstr' EQ STRING | 'otherstr' EQ STRING
    ;
column_split
    : field tc_option* where_clause?
    ;

/*
    cluster
    cluster   命令根据事件之间的相似度对事件进⾏分组。除⾮您指定了不同的字段，否则   cluster   将根据   _raw   字段的内
    容对事件进行分组。默认的分组⽅法为：把事件细分为若⼲术语  ( match=termlist ) ，然后再计算事件之间的⽮量。若
    您希望命令可以更有效地区分事件分组的标准，请为   t

    示例
    1、index=_internal source=*splunkd.log* log_level!=info | cluster showcount=true | table cluster_count _raw | sort -
    cluster_count
    2、... | cluster showcount=t | sort cluster_count
    3、error | cluster t=0.9 showcount=t | sort - cluster_count | head 20
    4、... | cluster labelonly=t showcount=t | sort - cluster_count, cluster_label, _time | dedup 5 cluster_label

*/
pipe_command_cluster
    : 'cluster'slc_options*
    ;

slc_options
    : 't' EQ NUMBER | 'delims' EQ STRING | 'showcount' EQ bool | 'countfield' EQ field
        | 'labelfield' EQ field | 'field' EQ field | 'labelonly' EQ bool
        | 'match' EQ ('termlist' | 'termset' | 'ngramset')
    ;
/*
    cofilter命令定义
    使用命令来查找field1和field2值⼀起出现的次数。

    ... | cofilter user item
*/
pipe_command_cofilter
    : 'cofilter' field field
    ;

/*
    collect命令定义
    将搜索结果添加到指定的摘要索引中。在调用collect命令前必须创建摘要索引。
    命令有问题
    eventtypetag="download" | collect index=downloadcount

     因字符串STRING的定义问题，未通过测试collect index=mysummary marker="summary_type=vpn, summary_span=3600, summary_method=bin, search_name=\"vpn starts and stops\""
*/
pipe_command_collect
    : 'collect' ('index' EQ STRING) (collect_arg_options)*
    ;
collect_arg_options
    :  'addtime' EQ bool | ('file' EQ STRING) |  'host' EQ STRING |  'marker' EQ STRING
       'run_in_preview' EQ bool |  'spool' EQ bool | 'source' EQ STRING |
       'sourcetype' EQ STRING |  'testmode' EQ bool
    ;

/*
    concurrency命令定义
    Concurrency能测量事件数量，这些事件具有与每个事件的启动重叠的间隔。或者，此测量代表每个特定事件启动
    时正在运行的事件总数，包括该事件本身。此命令不会计量整个时间跨度内与特定事件重叠的事件总数。
	... |eval new_start = start - duration | concurrency start=new_start duration=duration
	无序参数问题
*/
pipe_command_concurrency
    : 'concurrency ' ('duration' EQ field) ('start' EQ field)? ('output' EQ field)?
    ;
/*
    concurrency命令定义
    Concurrency能测量事件数量，这些事件具有与每个事件的启动重叠的间隔。或者，此测量代表每个特定事件启动
    时正在运行的事件总数，包括该事件本身。此命令不会计量整个时间跨度内与特定事件重叠的事件总数。
	index=_internal | contingency log_level component maxcols=5
*/
pipe_command_contingency
    : 'contingency ' (( contingency_options*  field field ) |  (field field contingency_options*))
    ;

contingency_options
    : max_opts | min_cover | use_total | total_str
    ;

max_opts
    : 'maxrows' EQ INT  |  'maxcols' EQ INT
    ;

min_cover
    : 'mincolcover' EQ NUMBER | 'minrowcover' EQ NUMBER
    ;
use_total
    : 'usetotal' EQ bool
    ;
total_str
    : 'totalstr' EQ field
    ;

/*
    convert命令
    把字段值转换成数字值。除非使AS子句，否则新值将替换原始值。
    或者，您可以使用eval函数，如strftime()、strptime()或tostring()。
    sourcetype=sendmail | convert dur2sec(delay) dur2sec(xdelay)
*/
pipe_command_convert
    : 'convert ' ('timeformat' EQ STRING)? convert_function*
    ;

convert_function
    : functionCall ('AS' field)?
    ;

/*
    correlate命令
    计算不同字段之间的相关性。
    可以使用correlate命令查看数据中字段之间的同现概览。结果将以矩阵形式显示，其中两个字段的交叉表是一个
    单元值。该单元值表示两个字段同时存在于相同事件中的次数的百分比。
    结果特定的字段以 RowField 字段值命名，而与其相比的字段是其他字段的名称。
    注意：此命令会查看搜索结果集中所有字段之间的关系。如果要分析字段值之间的关系，请参阅  contingency  命
    令，该命令用于统计事件中字段值对的同现数量。
*/
pipe_command_correlate
    : 'correlate'
    ;

/*
    ctable counttable命令是contigency命令的别名
*/
pipe_command_ctable
    : pipe_command_contingency
    ;
pipe_command_counttable
    : pipe_command_contingency
    ;

/*
    datamodel命令
    检查数据模型或数据模型数据集，并搜索数据模型数据集。
    使用datamodel命令为所有或指定的模型及其数据集返回JSON。
    datamodel   搜索命令允许您从搜索界⾯中搜索现有的数据模型及其数据集。
    datamodel   命令属于生成命令，应该是搜索中的第⼀个命令。生成成命令前应使管道符|。
*/
pipe_command_datamodel
    : '|' 'datamodel' (datamodelname=STRING)? (datasetname=STRING)? pipe_command_search?
    ;

/*
    dbinspect
    在指定索引中返回有关数据桶的信息。如果使⽤  Splunk Enterprise ，此命令可帮助您了解数据驻留的位置，以便可以根据需要优化磁盘使⽤情况。
    splunk特有命令，对于elk而言，没有桶，但是有shard。
*/
pipe_command_dbinspect
    : pipe_command_null '|' 'dbinspect'
        ('index' EQ WC_STRING)*
        (('span' EQ time_span | timeformat=STRING) |  'corruptonly' EQ bool)*
    ;
/*
    delete命令，将搜索结果在索引中标记为删除状态，并不是真删除
    delete操作是不可逆操作，务必谨慎，如果想恢复数据只能重新索引数据。
    在实时数据处理中，无法使用delete命令。
*/
pipe_command_delete
    : 'delete'
    ;
/*
    delta命令
    使⽤特定数字字段的值来计算邻近结果之差。对于  field  为数字的所有事件，delta   命令将按搜索顺序计算某事件field  值与前⼀个事件  field  值之间的差值。delta   命令将把差值写入  newfield 。
	若未指定   newfield   参数，delta   命令将使⽤   delta(field)。
*/
pipe_command_delta
    : 'delta' field ('AS' field)? delta_p?
    ;
delta_p
	: 'p' EQ INT
	;

/*
    diff命令
    ⽐较两个搜索结果并返回逐⾏差异或⼆者的⽐较结果。欲⽐较的两组搜索结果由位置值   position1   和   position2   指
定。这两个值默认为  1  和  2 ，即⽐较前两个结果。
	根据默认设置，将⽐较两组搜索结果的⽂本（_raw   字段）。若需⽐较其他字段，使⽤   attribute   选择另⼀个字段即
可。
    ... | diff position1=9 position2=10 diffheader=true
*/
pipe_command_diff
    : 'diff'  ( 'position1' EQ INT  | 'position2' EQ INT | 'attribute' EQ STRING  |  'diffheader' EQ bool  | 'context' EQ bool | 'maxlen' EQ INT )*
    ;

/*
    erex命令
*/
pipe_command_erex
    : field 'examples' EQ STRING ('counterexamples' EQ STRING)? ('fromfield' EQ field)?
     ('maxtrainers' EQ INT)?
    ;

/*
    eval命令
*/
pipe_command_eval
    :'eval ' assign_expr (','assign_expr)*
    ;

/*
    eventcount命令
*/
pipe_command_eventcount
    : pipe_command_null '|' 'eventcount ' ('index' EQ STRING)? ('list_vix' EQ bool)? ('report_size' EQ INT)?
    ;

/*
    eventcount命令
    待丰富
*/
pipe_command_eventstats
    : 'eventstats ' ('allnum' EQ bool)? (stats_agg_term as_clause field)+ ('BY' split_by_clause)?
    ;

/*
    extract命令
    待丰富
*/
pipe_command_extract
    : 'extract ' extract_options? (extractor_name=STRING)
    ;

extract_options
    : 'clean_keys' EQ bool | 'kvdelim' EQ STRING | 'limit' EQ INT | 'maxchars' EQ INT |
      'mv_add' EQ bool | 'pairdelim' EQ STRING | 'reload' EQ bool | 'segment' EQ bool
    ;


/*
    fieldformat命令
    fieldformat   命令允许使用eval表达式，以在呈现结果时更改字段值的格式。可以改变格式，而须改变字段的原始值。
    稍后在搜索管道中使用的命令无法修改格式化的值。
    fieldformat   命令不会应用于导出数据的命令，例如outputcsv和output lookup命令。导出的数据会保留原始数据格
    式,而非显示格式。若想把显示格式应用于导出的数据，请使eval   命令，不要使用fieldformat命令。
*/
pipe_command_fieldformat
    : 'fieldformat ' field EQ eval_expr
    ;

/**
    fields命令
 */
pipe_command_fields
    : 'fields ' SUB? id_list
    ;

/**
    fieldsummary
 */
pipe_command_fieldsummary
    : 'fieldsummary' ('maxvals' EQ INT)? wc_field_list?
    ;

/**
    filldown
 */
pipe_command_filldown
    : 'filldown' wc_field_list?
    ;

/**
    fillnull
 */
pipe_command_fillnull
    : 'fillnull' field_list?
    ;

/**
    findtypes
    使⽤搜索结果并创建⼀个潜在事件类型列表，以⽣成建议的事件类型。最多分析  5000  个事件，以发现事件类型。
 */
pipe_command_findtypes
    : 'findtypes' ('max' EQ INT)  'notcovered'?  'useraw'?
    ;

/**
    folderize
 */
pipe_command_folderize
    : 'folderize ' ('attr' EQ STRING) ('sep' EQ STRING)? ('size' EQ STRING)? ('minfolders' EQ INT)?
      ('maxfolders' EQ INT)?
    ;

/**
    foreach
    待丰富
 */
pipe_command_foreach
    : 'foreach '
    ;

/*
    format
    待丰富
*/
pipe_command_format
    : 'format '
    ;

/*
    from
    待丰富
*/
pipe_command_from
    : pipe_command_null '|' 'from '  dataset_type ':' dataset_name
    ;
dataset_type
    : 'datamodelinputlookup' | 'savedsearch'
    ;
dataset_name
    : ID
    ;


/*
    gauge
*/
pipe_command_gauge
    : 'gauge' field range_value
    ;
range_value
    : NUMBER ({\s} NUMBER)*
    ;

/*
    gentimes
*/
pipe_command_gentimes
    : 'gentimes' ('start' EQ timestamp) ('end' EQ timestamp)? ('increment' EQ INT('s' | 'm' | 'h' | 'day'))?
    ;

timestamp
    : 'MM/DD/YYYY'(':HH:MM:SS')? | INT
    ;

/*
    geom命令把以个名为geom的字段添加到每个事件。该字段JSON地理数据结构。这些地理数据结构用于创建Choropleth地图可视化。
*/
pipe_command_geom
    : 'geom'  (featureCollection)? ('allFeatures' EQ bool)? ('featureIdField' EQ STRING)?
      ('gen' EQ NUMBER)? ('min_x' EQ NUMBER)? ('min_y' EQ NUMBER)? ('max_x' EQ NUMBER)? ('max_y' EQ NUMBER)?
    ;

featureCollection
    : geo_lookup=STRING
    ;


/*
    geomfilter指定边框的各点，勇于剪辑Choropleth地图。
*/
pipe_command_geomfilter
    : 'geomfilter' ('min_x' EQ NUMBER)? ('min_y' EQ NUMBER)? ('max_x' EQ NUMBER)? ('max_y' EQ NUMBER)?
    ;

/*
    使用geostats命令生成成统计信息，以在地图上显示地理数据并汇总这些数据。
*/
pipe_command_geostats
    : 'geostats' ('translatetoxy' EQ bool)? ('latfield' EQ field)? ('longfield' EQ field)? ('globallimit' EQ INT)?
                 ('locallimit' EQ INT)? ('outputlatfield'EQ STRING)? ('outputlongfield' EQ STRING)?
                 ('binspanlat' EQ NUMBER)? ('binspanlong' EQ NUMBER)? ('maxzoomlevel' EQ INT)?
                 stats_agg_term column_split_by_clause?
    ;

/**
    head命令,按照搜索顺序返回前n个
*/
pipe_command_head:
    'head ' 'limit'? EQ INT?
    ;

/**
    hightlight命令,在web界面中高亮显示
*/
pipe_command_highlight
    :'hightlight' STRING
    ;

/*
    history
    描述描述
    使用此命令查看当前用户的搜索历史。以事件集或表形式显示搜索历史。
*/
pipe_command_history
    : 'history' ('events' EQ bool)?
    ;

/*
    input
    没理解这个命令
*/
pipe_command_input
    : 'input'
    ;

/*
    inputcsv
    没理解这个命令
*/
pipe_command_inputcsv
    : pipe_command_null '|' 'inputcsv' ('dispatch' EQ bool)? ('append' EQ bool)?
        ('start' EQ INT)? ('max' EQ INT)? ('events' EQ bool)?
        filename=STRING where_clause?
    ;

/*
    inputlookup
    使用inputlookup命令搜索查找表的内容。查找表可以是CSV查找或KV存储查找。
*/
pipe_command_inputlookup
    : pipe_command_null '|' 'inputlookup' ('append' EQ bool)? ('start' EQ INT)? ('max' EQ INT)?
        (filename=STRING | tablename=STRING)
        where_clause?
    ;

/*
    iplocation
    使用第三方数据库IP地址提取位置信息。此命令支持IPv4和IPv6。
*/
pipe_command_iplocation
    : 'iplocation' ('prefix' EQ STRING)? ('allfields' EQ bool)? ('lang' EQ STRING)?
        ip_address_fieldname=field
    ;

/*
    join
    使⽤ join命令合并子搜索和主搜索的结果。每个结果集必须要有⼀个或多个共同的字段。还可以使用selfjoin命
    令将搜索结果集与其自身合并。
*/
pipe_command_join
    : 'join' join_options* field_list? subsearch
    ;

join_options
    : 'type' EQ ('inner' | 'left' | 'right') | 'usetime' EQ bool
        'earlier' EQ bool | 'overwrite' EQ bool | 'max' EQ INT
    ;

subsearch
    : '[' STRING ']'
    ;

/*
    kmeans
    k均值聚类算法
*/
pipe_command_kmeans
    : 'kmeans' kmeans_options? field_list
    ;

kmeans_options
    : 'reps' EQ INT| 'maxiters' EQ INT | 't' EQ NUMBER | 'k' EQ (INT | INT '-' INT) |
        'cfield' EQ field | distype | 'showcentroid' EQ bool
    ;
/*
    指定要使用的距离指标。l1 , l1norm 和 cb 距离指标等同于 cityblock。l2 , l2norm 和sq 等同于 sqeuclidean
    或 sqEuclidean。cos 距离指标等同于 cosine。
*/
distype
    :  'dt' EQ (( 'l1' | 'l1norm' | 'cityblock' | 'cb' )
                    | ( 'l2' | 'l2norm' | 'sq' | 'sqeuclidean' ) | ( 'cos' | 'cosine'))
    ;
/*
    kvform
    基于⼀个描述如何提取值的表单模板从事件中提取键 / 值对。
*/
pipe_command_kvform
    : 'kvform' ('form' EQ STRING)? ('field' EQ field)
    ;

/*
loadjob
加载先前完成的搜索任务的事件或结果。要加载的项⽬按搜索任务  id  或已计划的搜索名称以及当前搜索时间范围来
识别。如果提供保存的搜索的名称并且在该范围内找到多个项⽬，将加载最新的项⽬。
搜索头群集仅在保存的计划搜索上才能运行loadjob命令。搜索头群集在其复制的结果或项目上运行搜索。无法在临时或实时搜索中
运行 loadjob 命令。
*/
pipe_command_loadjob
    : pipe_command_null '|' 'loadjob' (sid = STRING | savedsearch) ('result-event' EQ bool)?
        delegate? artifact_offset? ignore_running?
    ;
savedsearch
    : 'user-string' ':' 'app-string' ':' 'search-name-string'
    ;
delegate
    : 'job_delegate' EQ STRING
    ;
artifact_offset
    : 'artifact_offset' EQ INT
    ;
ignore_running
    : 'ignore_running' EQ bool
    ;

/*
    localize
    返回找到的搜索结果所属时间范围的列表。
*/
pipe_command_localize
    : 'localize' maxpause? timeafter? timebefore?
    ;

maxpause
    : 'maxpause' EQ INT ('s' | 'm' | 'h' | 'd')?
    ;
timeafter
    : 'timeafter' EQ INT ('s' | 'm' | 'h' | 'd')?
    ;
timebefore
    : 'timebefore' EQ INT ('s' | 'm' | 'h' | 'd')?
    ;

/*
    localop
    描述描述
    只在远程对等方执行后续命令。反之，指示搜索在本地运行后续命令。
    localop   命令强制后续命令成为  mapreduce  流程简化步骤的⼀部分。
*/
pipe_command_localop
    : 'localop'
    ;

/*
    lookup
*/
pipe_command_lookup
    : 'lookup'  (local = bool)? (update = bool)? ('lookup-table-name' EQ STRING) lookup_field_list?
        lookup_output?
    ;
lookup_field_list
    : (lookup_field=field ('AS' event_field=field)?)  (',' lookup_field=field ('AS' event_field=field))*
    ;
lookup_output
    : ('OUTPUT' | 'OUTPUTNEW') lookup_field_list?
    ;

/*
    makecontinuous
    通过在没有数据的时间段添加空数据桶以及量化存在数据的时间段来使得 X 轴上的字段在数字上连续。可用chart
    和timechart命令调用  X  轴字段。
*/
pipe_command_makecontinuous
    : 'makecontinuous' field? bin_options
    ;

/*
    makemv
    通过使用简单的字符串分隔符（可以是多字符）拆分单值字段，将此字段转换为多值字段。或者，也可以用 regex 拆分字段。
*/
pipe_command_makemv
    : 'makemv' ('delim' EQ STRING | 'tokenizer' EQ STRING)?
        ('allowempty' EQ bool)? ('setsv' EQ bool)? field
    ;

/*
    makeresults
    生成指定数量的搜索结果。如果未指定任何可选参数，则此命令在本地计算机上运行，并生成⼀个仅带有 _time 字段的结果。
*/
pipe_command_makeresults
    : | 'makeresults' (count=INT)? (annotate=bool)? (splunk_server=STRING)? (splunk_server_group=STRING)?
    ;

/*
    map 命令是⼀个针对每个输⼊事件或结果重复运行搜索的循环运算符。您可以在已保存的搜索或临时搜索上运行 map 命令。
    1.使用保存的搜索命令
    error | localize | map mytimebased_savedsearch
    2.映射开始和结束时间值 映射开始和结束时间值
    ... | map search="search starttimeu::$start$ endtimeu::$end$" maxsearches=10
*/
pipe_command_map
    : 'map' WS  (searchoption | savedsplunkoption) ('maxsearches' EQ INT)?
    ;

/*
    metadata 命令从指定的索引或分布式对等搜索节点返回数据来源、来源类型或主机的列表。metadata 命令返回随着时
    间累积的信息。您可以使用时间范围挑选器查看特定时间范围（如过去7天）的索引快照。
*/
pipe_command_metadata
    : pipe_command_null '|'  'metadata' ('type' EQ metadata_type) ('index' EQ STRING)* ('splunk_server' EQ WC_STRING)*
                    ('splunk_server_group' EQ  WC_STRING)*
    ;
metadata_type
    : 'hosts' | 'sources' | 'sourcetypes'
    ;

/*
    metasearch
    根据  <logical-expression>  中的条件从索引中检索事件metadata。Metadata 字段包括 source、sourcetype、
    host、 _time、 index 和 splunk_server。
*/
pipe_command_metadatasearch
    : pipe_command_null '|' 'metadatasearch' logical_expr
    ;

/*
    mstats
    待丰富
*/
pipe_command_mstats
    : 'mstats'
    ;

/*
    multikv
    从表格形式的事件中提取字段值，比如  top、netstat 和 ps 等的结果。multikv 命令针对每个表格行创建⼀个新事
    件，并从表格的标题行中指派字段名称。
*/
pipe_command_multikv
    : 'multikv'
    ;

/*
    multisearch
*/
pipe_command_multisearch
    : 'multisearch'
    ;

/*
    mvcombine
*/
pipe_command_mvcombine
    : 'mvcombine' WS ('delim' EQ STRING)? field
    ;

/*
    mvexpand
*/
pipe_command_mvexpand
    : 'mvexpand' field ('limit' EQ INT)?
    ;

/*
    nomv
*/
pipe_command_nomv
    : 'nomv' field
    ;

/*
    outlier
*/
pipe_command_outlier
    : 'outlier' outlier_options field_list?
    ;

outlier_options
    : 'action' EQ ('remove' | 'rm' | 'transform' | 'tf') | 'mark' EQ bool | 'param' EQ INT | 'uselower' EQ bool
    ;

/*
    outputcsv
    如果有Splunk Enterprise，则该命令把搜索结果保存到$SPLUNK_HOME/var/run/splunk/csv目录内本地搜索头上指
    定的CSV文件中。更新到$SPLUNK_HOME/var/run/*.csv，使用outputcsv。
*/
pipe_command_outputcsv
    : 'outputcsv' ('append' EQ bool)? ('create_empty' EQ bool)? ('dispatch' EQ bool)? ('usexml' EQ bool)?
      ('singlefile' EQ bool)? (filename=STRING)?
    ;

/*
    outputlookup
    将搜索结果写入您指定的静态查找表或KV存储集合中。
*/
pipe_command_outputlookup
    : pipe_command_null '|' 'outputlookup' ('append' EQ bool)? ('create_empty' EQ bool)? ('max' EQ INT)
        ('key_field' EQ field)? ('createinapp' EQ bool)? (filename = STRING | tablename = STRING)
    ;

/*
    outputtext
    将结果的原始文本(_raw)输出到_xml字段中。
*/
pipe_command_outputtext
    : 'outputtext' ('usexml' EQ bool)?
    ;

/*
    overlap
    待丰富
*/
pipe_command_overlap
    : 'overlap'
    ;

/*
    pivot
    待丰富
*/
pipe_command_pivot
    : pipe_command_null '|' 'pivot' ('datamodel-name' EQ STRING)? ('object-name' EQ STRING)? pivot_element
    ;

pivot_element
    : 'pivot_element'
    /*(<cellvalue>)* splitrow_rowvalue* splitcol_colvalue* (FILTER logical_expr)*
        limit_expression* ('ROWSUMMARY' bool)* ('COLSUMMARY' bool)* ('SHOWOTHER' bool)*
        ('NUMCOLS' INT)* //(rowsort [options])*没看懂，留待以后完善*/
    ;

cellvalue
    : functionCall 'AS' label=STRING
    ;

splitrow_rowvalue
    : 'SPLITROW' field ('AS' label=STRING)? ('RANGE' ('start' EQ value=INT) ('end' EQ value=INT)
        ('max' EQ INT) ('size' EQ INT))?
        ('PERIOD' ('auto' | 'year' | 'month' | 'day' | 'hour' | 'minute' | 'second'))?
        ('TRUELABEL' STRING)? ('FALSELABEL' STRING)
    ;
splitcol_colvalue
    : 'SPLITCOL' field ('RANGE' ('start' EQ value=INT) ('end' EQ value=INT)
        ('max' EQ INT) ('size' EQ INT))?
        ('PERIOD' ('auto' | 'year' | 'month' | 'day' | 'hour' | 'minute' | 'second'))?
        ('TRUELABEL' STRING)? ('FALSELABEL' STRING)
    ;

limit_expression
    : 'LIMIT' field 'BY' limittype=('top' | 'bottom') number=INT stats_agg_term
    ;

/*
    predict命令
    预测⼀个或多个时间系列数据的值。该命令还可以填充时间系列中缺失的数据，并为接下来的几个时间步骤提供预测。
*/
pipe_command_predict
    : 'predict' field_list ('AS' newfield=field)? predict_options?
    ;

predict_options
    : ('algorithm' EQ ('LL' | 'LLT' | 'LLP' | 'LLP5' | 'LLB' | 'BiLL'))
        | 'correlate_field' EQ field
        | 'future_timespan' EQ NUMBER
        | 'holdback' EQ NUMBER
        | 'period' EQ NUMBER
        | 'suppress' EQ bool
        | 'lowerXX' EQ field
        | 'upperYY' EQ field
    ;

/*
    rangemap
    使用rangemap 命令将数字字段中的各值进行分类。此命令将为每个事件添加⼀个名为range的新字段，并在range字
    段中显示其类别。range 字段中的各值基于指定的数字范围。
*/
pipe_command_rangemap
    : 'rangemap' field (attribute_name=STRING EQ numberric_range)* ('default' EQ STRING)?
    ;

numberric_range
    : NUMBER '-' NUMBER
    ;

/*
    rare
    显示最不常见的字段值
*/
pipe_command_rare
    : 'rare' top_options? field_list column_split_by_clause?
    ;
top_options
    : 'countfield' EQ STRING | 'limit' EQ INT | 'percentfield' EQ  STRING | 'showcount' EQ bool |
      'showperc' EQ bool
    ;

/*
    regex
    命令将删除与指定正则表达式不匹配的结果。
*/
pipe_command_regex
    : 'regex' (field EQ regex_expression | field '!=' regex_expression | regex_expression)
    ;
//该正则表达式必须为PCRE库支持持且与Perl兼容的正则表达式。需要用双引号引起来。
regex_expression
    : STRING
    ;

/*
    relevancy
    根据事件_raw 字段与'search'的关键字的匹配程度来计算事件与查询的匹配程度。结果保存于名为
    "relevancy"  的字段中。用于检索匹配程度最高的事件/文档，而不是默认的基于时间的顺序。事件的搜索关键字越
    稀少、使用越频繁、术语越少，则相关性越高。例如，在搜索  disk error  时，与使用⼀次'disk'、使用多次
    'error'  的非常大的事件相比，更偏向于使用多次'disk'（不常⽤的术语）而只使用一次'error'的短的事件/文档。
*/
pipe_command_relevancy
    : 'relevancy'
    ;

/*
    reltime命令
    创建⼀个名为  'reltime'  的相对时间字段，将此字段设置为  'now'  与  '_time'  之间的差值并用易于理解的方式表
    示。易于理解的值类似于 “5  天前 ” 、 “1  分钟前 ” 、 “2  年前 ” 等。
*/
pipe_command_reltime
    : 'reltime'
    ;

/*
    rename命令
*/
pipe_command_rename
    : 'rename ' as_clause+;
/*
    as 子句
*/
as_clause
    : ID 'AS' STRING;

/*
    repplace命令
    将字段值替换为您指定的值。将只出现⼀次的第⼀个字符串替换为指定字段中的另⼀个字符串。
    若未指定⼀个或多个字段，将替换所有字段中的值。
*/
pipe_command_replace
    : 'replace' (WC_STRING 'WITH' WC_STRING)+ ('IN' field_list)?
    ;

/*
    rest   命令读取  Splunk REST API  端点，并将资源数据返回成搜索结果。
*/
pipe_command_rest
    : '|' 'rest' rest_uri ('count' EQ INT)? ('splunk_server' EQ WC_STRING)? ('splunk_server_group' EQ WC_STRING)*
        ('timeout' EQ INT)? rest_arg_kv*
    ;

//待改进
rest_uri
    : STRING
    ;

rest_arg_kv
    : ID EQ STRING
    ;

/*
    return
    返回子搜索中的值。
    待改进
*/
pipe_command_return
    : 'return' //count=INT [<alias>=<field>...][<field>...][$<field>...]
    ;

/*
    reverse
    颠倒结果集的顺序
*/
pipe_command_reverse
    : 'reverse'
    ;

/*
    rex命令
    使用该命令既可以通过以正则表达式命名的群组提取字段，也可以通过  Sed  表达式替换或取代字段中的字符。
    rex命令将把指定字段的值与未定位的正则表达式进行匹配，并将命令的组提取到名称对应的字段中。若未指定字
    段，正则表达式将应用于_raw字段。
    注意：针对  _raw  字段运行可能会影响性能。
*/
pipe_command_rex
    : 'rex' ('field' EQ field)?
        ( regex_expression (max_match=INT)? ('offset_field' EQ field)?  | ('mode' EQ 'sed' sed_expression))
    ;
sed_expression
    : STRING
    ;

/*
    rtorder
    对来自实时搜索的事件进⾏缓冲，以尽可能按时间顺序的升序发出事件。
    rtorder 命令将创建获取输入事件的流事件缓冲区，按时间顺序的升序将这些事件存储到缓冲区，并按照相同的顺序
    从缓冲区发出这些事件。不过，仅当当前时间在事件的时间戳之后至少达到  buffer_span  所指定的时间跨度时，这
    些事件才会发出。
    如果超出缓冲区的最大大小，也会从缓冲区发出事件。
    如果在先前已发出的事件之前就以输⼊形式接收某个事件，则除非  discard  选项设置为  true ，否则将立即发出无序
    事件。如果  discard  设置为  true ，将始终放弃无序事件，从而保证输出始终严格以时间顺序的升序排列。
*/
pipe_command_rtorder
    : 'rtorder' ('discard' EQ bool)? ('buffer_span' EQ time_span)? ('max_buffer_size' EQ INT)?
    ;

/*
    run
    script命令的别名
*/
pipe_command_run
    : pipe_command_script
    ;

/*
    savedsearch
*/
pipe_command_savedsearch
    : pipe_command_null '|' 'savedsearch' savedsearch_name=STRING savedsearch_options*
    ;
savedsearch_options
    : ('nosubstitution' EQ bool) | 'replacement' EQ STRING
    ;

/*
    script命令,调用脚本
*/
pipe_command_script:
    ('script' | 'run') scriptName=ID functionParamList
    ;

/*
    scrub
    通过使用保持相同单词长度的虚构值替换标识数据，如用户名、ip  地址、域名等，使搜索结果匿名。例如，它可以
    将字符串user=carol@adalberto.com变为user=aname@mycompany.com。这样能够在不泄露机密或私人信息的情
    况下共享日志数据。
*/
pipe_command_scrub
    : 'scrub' ('public-terms' EQ filename=STRING)? ('private-terms' EQ filename=STRING)?
        ('name-terms' EQ filename=STRING)? ('dictionary' EQ filename=STRING)?
        ('timeconfig' EQ filename=STRING)? ('namespace' EQ STRING)?
    ;

/*
    search命令
    表达一个搜索条件，例如index="test" * AND host='192.168.31.1' AND field1 > 20，AND可忽略，默认的语义是AND，
    如果想表达OR语义，则必须写OR
*/

pipe_command_search
    : ('search ')? logical_expr
    ;

searchoption
    : 'search' EQ STRING
    ;
savedsplunkoption
    : STRING
    ;

/*
    searchtxn
    快速返回匹配到交易类型且包含特定文本的交易事件。
*/
pipe_command_searchtxn
    : pipe_command_null '|' 'searchtxn' transaction_name ('max_terms' EQ INT)? ('use_disjunct' EQ bool)?
      ('eventsonly' EQ bool)? search_string=STRING
    ;
/*
    transaction_type是transactiontypes.conf中定义的stantz
*/
transaction_name
    : transaction_type=STRING
    ;

/*
    selfjoin
*/
pipe_command_selfjoin
    : 'selfjoin' selfjoin_options* field_list
    ;
selfjoin_options
    : 'overwrite' EQ bool | 'max' EQ INT | 'keepsingle' EQ bool
    ;

/*
    sendemail
    发送电子邮件
*/
pipe_command_sendemail
    : 'sendemail' ('to' EQ email_list)
        ('from' EQ email_list)?
        ('cc' EQ email_list)?
        ('bcc' EQ email_list)?
        ('subject' EQ STRING)?
        ('format' EQ ('csv' | 'table' | 'raw'))?
        ('inline' EQ bool)?
        ('sendresults' EQ bool)?
        ('sendpdf' EQ bool)?
        ('priority' EQ ('highest' | 'high' | 'normal' | 'low' | 'lowest'))?
        ('server' EQ STRING)?
        ('width_sort_columns' EQ bool)?
        ('graceful' EQ bool)?
        ('content_type' EQ ('html' | 'plain'))?
        ('message' EQ STRING)?
        ('sendcsv' EQ bool)?
        ('use_ssl' EQ bool)?
        ('use_tls' EQ bool)?
        ('pdfview' EQ STRING)?
        ('papersize' EQ ('letter' | 'legal' | 'ledger' | 'a2' | 'a3' | 'a4' | 'a5'))?
        ('paperorientation' EQ ('portrait' | 'landscape'))?
        ('maxinputs' EQ INT)?
        ('maxtime' EQ INT ( 'm' | 's' | 'h' | 'd')?)?
        ('footer' EQ STRING)?
    ;
email_list
    : 'abc@126.com'(',' 'abc@126.com')*
    ;

/*
    set命令
    对子搜索与子搜索执行 set  操作。
*/
pipe_command_set
    : pipe_command_null '|' 'set' ('union' | 'diff' | 'intersect') subsearch subsearch
    ;

/*
    setfields
    将所有结果的字段值设置为常量值。
*/
pipe_command_setfields
    : 'set' (ID EQ STRING)*
    ;

/*
    sichart
*/
pipe_command_sichart
    : 'sichart'
    ;

/*
    sirare
*/
pipe_command_sirare
    : 'sirare'
    ;

/*
    sistats
*/
pipe_command_sistats
    : 'sistats'
    ;

/*
    sitimechart
*/
pipe_command_sitimechart
    : 'sitimechart'
    ;

/*
    sitop
*/
pipe_command_sitop
    : 'sitop'
    ;

/*
    sort命令,排序
    INT参数为返回数量限制，不填写默认返回所有
    sort_by_clause是排序的规则，按照哪些字段排序，降序还是升序，不填写默认降序
*/
pipe_command_sort
    : 'sort ' INT? sort_by_clause;

sort_by_clause
    : id_list ('desc'|'esc')?
    ;


/**
    spath命令,从json、xml中提取数据或者属性
*/
pipe_command_spath
    : 'spath ' ('input' EQ ID) ('output' EQ ID) ('path' EQ STRING)?('default' EQ (INT | STRING))?
    ;


/*
    stats命令,统计函命令
*/
pipe_command_stats
    :'stats ' (stats_agg_term 'BY' split_by_clause)?
    ;

/*
    strcat
*/
pipe_command_strcat
    : 'strcat' ('allrequired' EQ bool)? source_fields dest_field=field
    ;

source_fields
    : (field | STRING)*
    ;

/*
    streamstats
    待完善
*/
pipe_command_streamstats
    : 'streamstats'
    ;
/*
    table
    将返回仅由参数中指定的字段所形成的表格。各列按字段的指定顺序进行显示。列标题为字段名称。行为
    字段值。每行表示⼀个事件。
*/
pipe_command_table
    : 'table' wc_field_list
    ;

/*
    tags
*/
pipe_command_tags
    : 'tags'  ('outputfield' EQ field)? ('inclname' EQ bool)? ('inclvalue' EQ bool)? field_list
    ;

/**
    tail命令,按照搜索顺序返回后n个
*/
pipe_command_tail:
    'tail ' 'limit'? EQ INT?
    ;

/*
    timechart命令
*/
pipe_command_timechart
    :'timechart ' bin_options ((single_agg_term 'BY | by' split_by_clause)|(eval_expr 'BY' split_by_clause))?
    ;

single_agg_term
    : single_agg ('(' field ')')?
    ;

single_agg
    : 'count'
    | 'sum'
    | 'avg'
    | 'max'
    | 'min'
    ;

/*
    timewrap
*/
pipe_command_timewrap
    : 'timewrap' timewrap_span ('align' EQ ('now' | 'end'))? ('series' EQ ('relative' | 'exact' | 'short'))?
       ('time_format' EQ STRING)?
    ;
timewrap_span
    : INT? time_scale_all
    ;

/*
   top
   显示字段最常见的值。
*/
pipe_command_top
    : 'top'  N=INT top_options* field_list column_split_by_clause?
    ;

/*
    transaction
    交易命令根据满⾜各种约束的事件查找交易。交易的构成内容包括：每个成员的原始⽂本（_raw   字段）、最早期成员
    的时间和日期字段，以及每个成员所有其他字段的并集。
    此外，transaction   命令还把两个字段添加到原始事件、duration   和   eventcount。duration   字段中的值为交易中第⼀个
    事件与最后⼀个事件的时间戳之差。eventcount   字段中的值为交易中事件的数量。

    待完善
*/
pipe_command_transaction
    : 'transaction' field_list? ('name' EQ transaction_name)? txn_definition_options*
        memcontrol_options* rendering_options*
    ;
txn_definition_options
    :   'maxspan' EQ INT | 'maxpause' EQ INT (second | minute | hr | day)? | 'maxevents' EQ INT | 'startswith' EQ filter_expr | 
        'endswith' EQ filter_expr |'connected' EQ bool | 'unifyends' EQ bool | 'keeporphans' EQ bool
    ;
filter_expr
    : logical_expr
    ;    
memcontrol_options
    : 'memcontrol_options'
    ;

txt_definition_options
    : 'txt_definition_options'
    ;
rendering_options
    : 'rendering_options'
    ;

/*
    transpose
    将指定的行（搜索结果）数以列（字段值列表）形式返回，以便每个搜索行都变成⼀列。
*/
pipe_command_transpose
    : 'transpose' INT? ('column_name' EQ STRING)? ('header_field' EQ field)? ('include_empty' EQ bool)?
    ;

/*
    trendline
    计算字段的移动平均线：简单移动平均线  (sma) 、指数移动平均线  (ema)  和加权移动平均线  (wma) 。输出将写入到
    新字段中，可以指定新字段。
*/
pipe_command_trendline
    : 'trendline' ( <trendtype> period=INT '(' field ')' ('AS' newfield=field)?)*
    ;
trendtype
    :  'sma' | 'ema' | 'wma'
    ;

/*
    tscollect
    命令使用索引字在定义的命名空间中段创建时间系列索引 时间系列索引  (tsidx)  文件。这些文件中的结果表是已
    索引的数据的子集。因此，之后可以使用  tstats   命令对这些  tsidx  问件执行搜索并提交报表，而不是搜索原始数
    据。由于搜索的是完整索引的子集，因此搜索的完成速度应比之前的方式要快。
    tscollect   可以在相同的命名空间中创建多个  tsidx  文件。当它确定当前正在创建的问件已经足够大时，它将开始创
    建⼀个新  tsidx 。
*/
pipe_command_tscollect
    : 'tscollect' (namespace=STRING)? ('squashcase' EQ bool)? ('keepresults' EQ bool)?
    ;

/*
     tstats命令
     执行 tsidx 文件中的索引字段上的统计查询。索引字段可以来自普通索引数据、 tscollect  数据或加速数据模型。
*/
pipe_command_tstats
    : '|' 'tstats'
            ( 'prestats' EQ bool | 'local' EQ bool |  'append' EQ bool | 'summariesonly' EQ bool |'allow_old_summaries' EQ bool |  'chunk_size' EQ INT)*
             stats_func*
             ('FROM' (namespace=STRING | 'sid' EQ tscollect_job_id=STRING | 'datamodel' EQ data_model_name=STRING ))?
             where_clause? (column_split_by_clause  ('span' EQ time_span)?)?
    ;

stats_func
    : ('count' | 'avg' | 'dc' | 'earliest' | 'estdc' | 'exactperc' | 'first' | 'last' | 'latest' | 'median'
        | 'max' | 'min' | 'mode' | 'perc' | 'p' | 'range' | 'stdev' | 'stdevp' | 'sum' | 'sumsq' | 'upperperc'
        | 'values' | 'var' | 'varp' ) '(' field ')' ('AS' field)?
    ;

/*
    typeahead
*/
pipe_command_typeahead
    : 'typeahead'
    ;

/*
    typelearner
    通过使用以前的搜索结果并创建⼀个可⽤作事件类型的潜在搜索列表，来⽣成建议的事件类型。根据默认设
    置，typelearner   命令最初按分组字段的值对事件进⾏分组。然后根据它们所含的关键字进⼀步统⼀并合并这些组。
*/
pipe_command_typelearner
    : pipe_command_null '|' 'typeahead' ('prefix' EQ STRING) ('count' EQ INT) ('max_time' EQ INT)? ('index' EQ STRING)?
      ('starttimeu' EQ INT)? ('endtimeu' EQ INT)? ('collapse' EQ bool)?
    ;

/*
    typer
    计算与已知事件类型匹配的搜索结果的  'eventtype'  字段。
*/
pipe_command_typer
    : 'typer'
    ;

/*
    union
    将两个或两个以上数据集中的结果合并到⼀个数据集中。其中⼀个数据集可以是⼀个结果集，然后通过管道符将结果
    传递给   union   命令并和第二个数据集合并。
*/
pipe_command_union
    : 'union' subsearch_options* data_set data_set*
    ;

subsearch_options
    : 'maxtime' EQ INT | 'maxout' EQ INT | 'timeout' EQ INT
    ;
data_set
    :  dataset_type ':' dataset_name | subsearch
    ;

/*
    uniq
    将对您传递给该命令的搜索结果进行过滤。此命令将与先前结果完全重复的所有搜索结果删除。此命令不含
    任何参数。
    注意：不建议对⼤型数据集运行此命令。
*/
pipe_command_uniq
    :'uniq'
    ;

/*
    untable
    将结果从表格格式转换为与  stats  输出类似的格式。此命令是  xyseries  命令的反向命令。
*/
pipe_command_untable
    : 'untable' x_field=field y_name_field=field y_data_field=field
    ;

/*
    where
    使用   eval   表达式过滤搜索结果。此搜索只保留表达式为true的结果。
*/
pipe_command_where
    : 'where' eval_expr
    ;
/*
    x11
    移除基于时间的数据系列的季节性模式，以便您可以看到数据中真实的趋势。此命令与  trendline  命令具有
    相同的⽤途，但它使⽤业内更流⾏、更成熟的  X11  ⽅法。
*/
pipe_command_x11
    : 'x11' ('add()' | 'multi()')? (period=INT)? field 'AS' newfield=field
    ;

/*
    xmlkv   命令
    自动从XML格式的数据中提取字段。例如，若XML在其 _raw 数据中包含以下值：<foo>bar</foo>，其中
    foo 是键而 bar 是值。
*/
pipe_command_xmlkv
    : 'xmlkv' ('maxinputs' EQ INT)
    ;

/*
    xmlunescape
    取消转义 xml 字符，包括  & 、 <, and >  等实体引用，使它们回归到对应的字符。例如，&amp; 变为 &。
*/
pipe_command_xmlunescape
    : 'xmlunescape' ('maxinputs' EQ INT)
    ;
/**
    xpath命令,从xml中提取属性或者数据
*/
pipe_command_xpath
    :'xpath ' ('outputfield' EQ ID) (xpath_str=STRING) ('field' EQ ID)?('default' EQ (INT | STRING))?
    ;
/*
    syseries
    将结果转换为适用于绘图的格式。
*/
pipe_command_xyseries
    : 'xyseries' ('grouped' EQ bool)? x_field=field  y_name_field=field y_data_field=field_list ('sep' EQ STRING)?
       ('format' EQ STRING)?
    ;



pipe_command_kafka
    : 'kafka' 'host='
    ;

pipe_command_null: WS;


/*
    按照列进行分组，等同于group by
*/
column_split_by_clause
    : 'BY' field_list
    ;
/*
    待续，参考bin命令
*/
row_split_by_clause
    : field bin_options?
    ;

//by子句
split_by_clause
    : id_list where_clause?
    ;

//where 子句
where_clause
    : 'where ' logical_expr
    ;


/**
    dedup命令,按照搜索顺序返回前n个
*/
pipe_command_dedup
    :'dedup ' num=INT? id_list? ('sortby' sort_by_clause)?
    ;


unaryOperator
    : '!' | '~' | '+' | '-' | NOT
    ;
/*comparisonOperator
    : '=' | '>' | '<' | '<' '=' | '>' '='
    | '<' '>' | '!' '=' | '<' '=' '>'
    ;*/

//OPERATORS. logical

AND:                                 'AND' | '&''&';
OR:                                  'OR' | '|''|';
NOT:                                 'NOT' | '!';
XOR:                                 'XOR';

logicalOperator : AND | OR ;

/*bitOperator
    : '<' '<' | '>' '>' | '&' | '^' | '|'
    ;*/

mathOperator
    : '*' | '/' | '%' | DIV | MOD | '+' | '-' | '--'
;

/*mathOperator
    : MUL | PLUS | MINUSMINUS | MINUS | DIV |MOD
;*/

constant
    : STRING | NUMBER
    ;

