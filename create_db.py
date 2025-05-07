import sqlite3
import bcrypt

def create_db():
    # Xóa database cũ nếu tồn tại
    try:
        import os
        if os.path.exists('data.db'):
            os.remove('data.db')
            print('✅ Đã xóa database cũ.')
    except Exception as e:
        print(f'⚠ Lỗi khi xóa database cũ: {e}')

    conn = sqlite3.connect('data.db')
    c = conn.cursor()
    
    # Tạo bảng users
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        branch TEXT NOT NULL,
        role TEXT NOT NULL
    )''')
    
    # Tạo bảng proposals
    c.execute('''CREATE TABLE IF NOT EXISTS proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        proposer TEXT,
        department TEXT,
        date TEXT,
        code TEXT,
        proposal TEXT,
        content TEXT,
        supplier TEXT,
        estimated_cost REAL,
        approved_amount REAL,
        notes TEXT,
        completed TEXT,
        branch TEXT
    )''')
    
    # Tạo tài khoản admin
    admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    c.execute('INSERT OR IGNORE INTO users (username, password, branch, role) VALUES (?, ?, ?, ?)',
              ('admin', admin_password, 'Trụ sở chính', 'admin'))
    
    # Tạo tài khoản cho 18 chi nhánh (2 tài khoản mỗi chi nhánh)
    branches = [
        "XDV-THAODIEN", "XDV-THAINGUYEN", "XDV-QUAN12", "XDV-QUAN7", 
        "XDV-NGHEAN", "XDV-KHANHHOA", "XDV-HANOI", "XDV-DANANG", 
        "XDV-CANTHO", "PTT-TRANDUYHUNG", "PTT-THAODIEN", "PTT-QUAN12", 
        "PTT-QUAN7", "PTT-NHATRANG", "PTT-NGOCHOI", "PTT-NGHEAN", 
        "PTT-LANDMARK81", "PTT-KHANHHOA"
    ]
    
    for branch in branches:
        branch_lower = branch.lower().replace("-", "_")
        for i in range(1, 3):  # Tạo 2 tài khoản: manager1, manager2
            username = f"{branch_lower}_manager{i}"
            password = bcrypt.hashpw('manager123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            c.execute('INSERT OR IGNORE INTO users (username, password, branch, role) VALUES (?, ?, ?, ?)',
                      (username, password, branch, 'branch'))
    
    conn.commit()
    print('✅ Đã tạo user admin và 36 tài khoản cho 18 chi nhánh với mật khẩu mã hóa.')
    conn.close()

if __name__ == '__main__':
    create_db()