import time, datetime

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