import time, datetime, urllib, re

def formatdate(timeval=None, localtime=False, usegmt=False):
    """Returns a date string as specified by RFC 2822, e.g.:
    
    Fri, 09 Nov 2001 01:08:47 -0000
    
    Optional timeval if given is a floating point time value as accepted by
    gmtime() and localtime(), otherwise the current time is used.
    
    Optional localtime is a flag that when True, interprets timeval, and
    returns a date relative to the local timezone instead of UTC, properly
    taking daylight savings time into account.
    
    Optional argument usegmt means that the timezone is written out as
    an ascii string, not numeric one (so "GMT" instead of "+0000"). This
    is needed for HTTP, and is only used when localtime==False.
    """
    if timeval is None:
        timeval = time.time()
        
    # Format the date according to RFC 2822
    if localtime:
        # Local time with timezone
        tuple_time = time.localtime(timeval)
        date_str = time.strftime("%a, %d %b %Y %H:%M:%S", tuple_time)
        if usegmt:
            # Append 'GMT' if usegmt is True
            date_str += " GMT"
        else:
            # Compute the local timezone offset
            offset = datetime.datetime.now() - datetime.datetime.utcnow()
            total_seconds = int(offset.total_seconds())
            sign = "+" if total_seconds > 0 else "-"
            hours_offset = abs(total_seconds) // 3600
            minutes_offset = (abs(total_seconds) % 3600) // 60
            date_str += " {}{:02d}{:02d}".format(sign, hours_offset, minutes_offset)
    else:
        # UTC/GMT time
        tuple_time = time.gmtime(timeval)
        date_str = time.strftime("%a, %d %b %Y %H:%M:%S", tuple_time)
        if usegmt:
            date_str += " GMT"
        else:
            date_str += " +0000"

    return date_str


def parse_url(url):
    """  
    parse url to plain path and query dictionary
    """
    parts = urllib.parse.urlsplit(url)
    path = parts.path
    query = urllib.parse.parse_qs(parts.query)
    return path, query


def get_filename_from_content_disposition(content_disposition):
    """
    Extracts filename from the Content-Disposition header.
    """
    if not content_disposition:
        return None
    filename_regex = r'filename\*?=(?:UTF-8\'\')?(.+)'  # Regex to extract filename
    matches = re.finditer(filename_regex, content_disposition, re.IGNORECASE)
    for match in matches:
        if match.group(1):
            # The filename might be URL-encoded
            filename = urllib.parse.unquote_plus(match.group(1).strip('"'))
            return filename
    return None

def join_path_query(path, query_params):
    # 初始化查询参数字符串
    query_string = ""
    # 遍历字典中的每个键值对
    for key, values in query_params.items():
        # 确保值是一个列表
        if not isinstance(values, list):
            values = [values]
        # 对于每个值，添加到查询字符串
        for value in values:
            if query_string:
                query_string += '&'
            query_string += urllib.parse.urlencode({key: value})
    
    # 构造完整的URL
    return urllib.parse.urlunsplit(('', '', path, query_string, ''))