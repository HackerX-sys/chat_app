from datetime import datetime

def timeago(dt):
    if not dt:
        return ''
        
    now = datetime.utcnow()
    diff = now - dt
    
    seconds = diff.total_seconds()
    minutes = seconds // 60
    hours = minutes // 60
    days = diff.days
    
    if seconds < 60:
        return 'just now'
    elif minutes < 60:
        return f'{int(minutes)} minutes ago'
    elif hours < 24:
        return f'{int(hours)} hours ago'
    elif days == 1:
        return 'yesterday'
    elif days < 7:
        return f'{days} days ago'
    else:
        return dt.strftime('%Y-%m-%d')
