# Week 07: Authentication & Authorization with Auth0 and Next.js

## 🎯 What You'll Learn

By the end of this tutorial, you'll understand:
- **Authentication**: Verifying WHO someone is (like showing your ID)
- **Authorization**: Determining WHAT they can access (like having a key to certain rooms)
- **Access Control**: Managing who can do what in your application

---

## 📚 Complete Beginner's Guide to Auth0 + Next.js

### **What is Auth0?**
Auth0 is a service that handles user login/logout for you. Instead of building your own login system (which is hard and risky), Auth0 does it securely for you.

**Real-world example**: Think of Auth0 like a security guard at a building. They check IDs, give out access badges, and make sure only authorized people get in.

---

## **PART 1: SETTING UP YOUR COMPUTER**

### Step 1: Install Required Software

You need three programs on your computer:

#### **A) Install Node.js** (The engine that runs our code)

1. Go to: `https://nodejs.org`
2. Click the **LTS** button (Long Term Support - the stable version)
3. Download and run the installer
4. Keep clicking "Next" until it installs
5. Restart your computer after installation

**Check if it worked:**
- Open **Command Prompt** (Windows) or **Terminal** (Mac)
  - Windows: Press `Windows Key + R`, type `cmd`, press Enter
  - Mac: Press `Command + Space`, type `terminal`, press Enter
- Type: `node --version`
- You should see something like `v20.10.0`

#### **B) Install VS Code** (Your code editor)

1. Go to: `https://code.visualstudio.com`
2. Download for your operating system
3. Install it (keep default settings)

#### **C) Install Git** (Version control - optional but recommended)

1. Go to: `https://git-scm.com`
2. Download and install
3. Use default settings

---

## **PART 2: CREATE YOUR AUTH0 ACCOUNT**

Auth0 is FREE for small projects (up to 7,000 users).

### Step 2: Sign Up for Auth0

1. **Go to**: `https://auth0.com`
2. Click **"Sign Up"** in the top right
3. Sign up with your email (or Google/GitHub)
4. Verify your email

### Step 3: Create Your Auth0 "Tenant"

**What's a tenant?** Think of it as your own private security office within Auth0.

1. After signing in, Auth0 will ask you to create a tenant
2. **Tenant Domain**: Choose a name like `myschool-dev` or `yourname-app`
   - This becomes: `myschool-dev.au.auth0.com`
3. **Region**: Choose the closest region to you (e.g., Australia, US)
4. Click **Create**

### Step 4: Create Your Application in Auth0

**What's an application?** Each website/app you build needs its own "application" in Auth0. It's like registering your building with the security company.

1. In Auth0 Dashboard, click **Applications** on the left
2. Click **Applications** again
3. Click **"+ Create Application"** button
4. Fill in:
   - **Name**: `My First Next.js App` (or anything you like)
   - **Type**: Select **"Regular Web Applications"** ✅
5. Click **"Create"**

### Step 5: Copy Your Secret Keys

**IMPORTANT**: These are like your building's security codes. Keep them secret!

You'll see a screen with tabs. Click the **"Settings"** tab.

**Copy these THREE values** (write them down or keep this tab open):

```
Domain: dev-xxxxxxxx.au.auth0.com
Client ID: AbCd1234XyZ... (long random string)
Client Secret: AbCd1234XyZ... (another long random string)
```

**⚠️ NEVER share your Client Secret publicly or put it on GitHub!**

### Step 6: Configure Callback URLs

**What are callback URLs?** After Auth0 logs someone in, it needs to know where to send them back. Like telling a taxi driver your home address.

Scroll down on the same Settings page to find these fields:

**1. Allowed Callback URLs** - Paste this:
```
http://localhost:3000/auth/callback
```

**2. Allowed Logout URLs** - Paste this:
```
http://localhost:3000
```

**3. Allowed Web Origins** - Paste this:
```
http://localhost:3000
```

**Click "Save Changes"** at the bottom! (Important!)

---

## **PART 3: CREATE YOUR NEXT.JS PROJECT**

### Step 7: Open Command Prompt / Terminal

**Windows:**
- Press `Windows Key + R`
- Type `cmd`
- Press Enter

**Mac:**
- Press `Command + Space`
- Type `terminal`
- Press Enter

### Step 8: Navigate to Where You Want Your Project

**Understanding folders:**
- `cd` means "change directory" (go to a folder)
- `mkdir` means "make directory" (create a new folder)

**Example** (adjust to your preference):

```bash
# Go to your Desktop
cd Desktop

# Create a folder for your projects
mkdir my-projects

# Go into that folder
cd my-projects
```

### Step 9: Create the Next.js Project

**Copy and paste this ENTIRE command** (one line):

```bash
npx create-next-app@15 auth0-nextjs-app --typescript --tailwind --eslint --app --src-dir --import-alias "@/*" --yes
```

**What this does:**
- `npx`: Run a command without installing it permanently
- `create-next-app@15`: Create a Next.js version 15 project
- `auth0-nextjs-app`: Your project name (you can change this)
- `--typescript`: Use TypeScript (safer coding)
- `--tailwind`: Include Tailwind CSS (for styling)
- `--app`: Use the new App Router
- `--src-dir`: Organize code in a `src` folder
- `--yes`: Accept all defaults

**Wait 1-3 minutes** while it downloads everything.

### Step 10: Enter Your Project Folder

```bash
cd auth0-nextjs-app
```

### Step 11: Open Project in VS Code

```bash
code .
```

(The dot means "current folder")

If that doesn't work:
1. Open VS Code manually
2. Click **File → Open Folder**
3. Select the `auth0-nextjs-app` folder

---

## **PART 4: INSTALL AUTH0 SDK**

### Step 12: Install Auth0 Package

In VS Code, open the **Terminal** (bottom panel), or use your command prompt:

```bash
npm install @auth0/nextjs-auth0@latest
```

**What this does:** Downloads the Auth0 library that connects your app to Auth0's service.

**Wait 30 seconds** for installation.

---

## **PART 5: CREATE CONFIGURATION FILES**

### Step 13: Create Your Secret Environment File

**What's an environment file?** It stores secret keys that only exist on YOUR computer, never uploaded to the internet.

1. In VS Code, in the left sidebar, **right-click** in the file list
2. Click **"New File"**
3. Name it **exactly**: `.env.local` (yes, starts with a dot!)
4. **IMPORTANT**: It should be at the ROOT of your project (same level as `package.json`)

### Step 14: Generate a Random Secret

We need to create a super-secret random code.

**In your terminal, run this:**

**Windows (Command Prompt):**
```cmd
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Mac/Linux:**
```bash
openssl rand -hex 32
```

You'll get something like: `a1b2c3d4e5f6...` (long random string)

**Copy this!** You'll use it in the next step.

### Step 15: Fill in Your Environment Variables

Open the `.env.local` file you just created and paste this:

```env
AUTH0_DOMAIN=YOUR_DOMAIN_HERE
AUTH0_CLIENT_ID=YOUR_CLIENT_ID_HERE
AUTH0_CLIENT_SECRET=YOUR_CLIENT_SECRET_HERE
AUTH0_SECRET=YOUR_RANDOM_SECRET_HERE
APP_BASE_URL=http://localhost:3000
```

**Now REPLACE the values:**

1. **AUTH0_DOMAIN**: Paste your domain from Step 5 (like `dev-xxxxx.au.auth0.com`)
2. **AUTH0_CLIENT_ID**: Paste your Client ID from Step 5
3. **AUTH0_CLIENT_SECRET**: Paste your Client Secret from Step 5
4. **AUTH0_SECRET**: Paste the random string from Step 14

**Example** (with fake values):
```env
AUTH0_DOMAIN=dev-abc123.au.auth0.com
AUTH0_CLIENT_ID=xYz123AbC456DeF789
AUTH0_CLIENT_SECRET=sUp3rS3cr3tK3y_n3v3rSh4r3
AUTH0_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
APP_BASE_URL=http://localhost:3000
```

**Save the file!** (Ctrl+S or Cmd+S)

---

## **PART 6: CREATE THE CODE FILES**

We're going to create several files. Follow carefully!

### Step 16: Create Folder Structure

In VS Code terminal:

```bash
mkdir -p src/lib src/components
```

**What this does:** Creates folders for our code organization.

### Step 17: Create `src/lib/auth0.ts`

1. In VS Code, **right-click** on the `src/lib` folder
2. Click **"New File"**
3. Name it: `auth0.ts`
4. Paste this code:

```typescript
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client();
```

**What this does:** Creates our Auth0 connection that we'll use throughout the app.

**Save** (Ctrl+S)

### Step 18: Create `src/middleware.ts`

1. **Right-click** on the `src` folder
2. Click **"New File"**
3. Name it: `middleware.ts`
4. Paste this code:

```typescript
import type { NextRequest } from "next/server";
import { auth0 } from "./lib/auth0";

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request);
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
```

**What this does:** Intercepts every page request to check if the user is logged in.

**Save**

### Step 19: Create Login Button Component

1. **Right-click** on `src/components`
2. **New File** → Name it: `LoginButton.tsx`
3. Paste:

```tsx
"use client";

export default function LoginButton() {
  return (
    <a
      href="/auth/login"
      className="inline-flex items-center justify-center rounded-lg px-5 py-3 font-semibold bg-sky-500 hover:bg-sky-600 text-slate-950 transition"
    >
      Log In
    </a>
  );
}
```

**What this does:** Creates a pretty button that takes users to the login page.

**Save**

### Step 20: Create Logout Button Component

1. In `src/components`, create: `LogoutButton.tsx`
2. Paste:

```tsx
"use client";

export default function LogoutButton() {
  return (
    <a
      href="/auth/logout"
      className="inline-flex items-center justify-center rounded-lg px-5 py-3 font-semibold bg-rose-500 hover:bg-rose-600 text-slate-950 transition"
    >
      Log Out
    </a>
  );
}
```

**Save**

### Step 21: Create Profile Component

1. In `src/components`, create: `Profile.tsx`
2. Paste:

```tsx
"use client";

import { useUser } from "@auth0/nextjs-auth0/client";

export default function Profile() {
  const { user, isLoading } = useUser();

  if (isLoading) {
    return (
      <div className="text-slate-300 text-sm">Loading user profile...</div>
    );
  }

  if (!user) return null;

  return (
    <div className="w-full rounded-xl bg-slate-800/60 border border-white/10 p-4 flex gap-4 items-center">
      <img
        src={user.picture ?? ""}
        alt={user.name ?? "User"}
        className="h-14 w-14 rounded-full object-cover border border-white/10"
        referrerPolicy="no-referrer"
      />
      <div className="min-w-0">
        <div className="font-semibold text-slate-100 truncate">
          {user.name}
        </div>
        <div className="text-slate-300 text-sm truncate">
          {user.email}
        </div>
      </div>
    </div>
  );
}
```

**What this does:** Displays the logged-in user's name, email, and profile picture.

**Save**

### Step 22: Replace the Home Page

1. Find and open: `src/app/page.tsx`
2. **Delete EVERYTHING** in the file
3. Paste this:

```tsx
import { auth0 } from "@/lib/auth0";
import LoginButton from "@/components/LoginButton";
import LogoutButton from "@/components/LogoutButton";
import Profile from "@/components/Profile";

export default async function Home() {
  const session = await auth0.getSession();
  const user = session?.user;

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
      <div className="w-full max-w-lg rounded-2xl bg-slate-900/60 border border-white/10 shadow-2xl p-8 space-y-6">
        <div className="flex flex-col items-center gap-3">
          <img
            src="https://cdn.auth0.com/quantum-assets/dist/latest/logos/auth0/auth0-icon.svg"
            alt="Auth0"
            className="h-10 w-10"
          />
          <h1 className="text-3xl font-bold text-center">Next.js + Auth0</h1>
          <p className="text-slate-300 text-center">
            Week 07: Authentication & Authorization Demo
          </p>
        </div>

        {user ? (
          <div className="space-y-4">
            <div className="text-emerald-400 font-semibold text-center">
              ✅ Successfully logged in!
            </div>
            <Profile />
            <div className="flex justify-center">
              <LogoutButton />
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-slate-300 text-center">
              Click below to log in via Auth0 Universal Login.
            </p>
            <div className="flex justify-center">
              <LoginButton />
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
```

**What this does:** Shows a login button if not logged in, or user profile + logout if logged in.

**Save**

---

## **PART 7: RUN YOUR APPLICATION**

### Step 23: Start the Development Server

In your VS Code terminal (or command prompt), type:

```bash
npm run dev
```

**What happens:**
- Your app starts running
- You'll see: `✓ Ready in 2s`
- And: `○ Local: http://localhost:3000`

### Step 24: Open Your App in Browser

1. Open your web browser (Chrome, Firefox, Edge, etc.)
2. Go to: `http://localhost:3000`

**You should see:** A dark-themed page with the Auth0 logo and a blue "Log In" button!

### Step 25: Test the Login!

1. Click the **"Log In"** button
2. You'll be redirected to Auth0's login page
3. Click **"Sign up"** (if this is your first time)
4. Enter your email and create a password
5. Auth0 will redirect you back to your app
6. **Success!** You should see:
   - ✅ Successfully logged in!
   - Your profile picture, name, and email
   - A red "Log Out" button

### Step 26: Test the Logout

1. Click the **"Log Out"** button
2. You'll be logged out and see the login page again

---

## **PART 8: UNDERSTANDING WHAT YOU BUILT**

### 🔐 Key Concepts Explained

#### **Authentication vs Authorization**

| Concept | What it Means | Example |
|---------|---------------|---------|
| **Authentication** | Proving who you are | Showing your student ID card |
| **Authorization** | Proving what you can access | Your ID shows you're allowed in certain buildings |

#### **How the Login Flow Works**

1. **User clicks "Log In"** → Goes to `/auth/login`
2. **Auth0 SDK redirects** → Takes user to Auth0's secure login page
3. **User enters credentials** → Auth0 verifies username/password
4. **Auth0 redirects back** → Sends user to `/auth/callback` with a token
5. **Session created** → Your app saves the user's login session
6. **User sees profile** → App displays "Successfully logged in!"

#### **Security Features You Get Free**

✅ **Password hashing** - Passwords are never stored in plain text  
✅ **HTTPS encryption** - All data sent securely  
✅ **Session management** - Automatic login/logout handling  
✅ **CSRF protection** - Prevents fake login requests  
✅ **Brute force protection** - Blocks repeated failed logins  

---

## **PART 9: COMMON PROBLEMS & SOLUTIONS**

### ❌ Problem 1: "Callback URL mismatch"

**Error:** You see an error about callback URLs not matching.

**Solution:**
1. Go to Auth0 Dashboard
2. Open your application settings
3. Check that "Allowed Callback URLs" contains **exactly**:
   ```
   http://localhost:3000/auth/callback
   ```
4. Click "Save Changes"
5. Restart your app: Stop the server (Ctrl+C) and run `npm run dev` again

### ❌ Problem 2: ".env.local not loading"

**Error:** Your app can't connect to Auth0.

**Solution:**
1. Make sure `.env.local` is in the **root** of your project (same folder as `package.json`)
2. Check that all values are filled in (no `YOUR_DOMAIN_HERE` left)
3. Restart the server: `npm run dev`

### ❌ Problem 3: "404 on /auth/login"

**Error:** You get "Page not found" when clicking login.

**Solution:**
1. Make sure `src/middleware.ts` exists
2. Check that you're using `--src-dir` structure
3. Restart the server

### ❌ Problem 4: "Module not found: @auth0/nextjs-auth0"

**Error:** Import errors in your code.

**Solution:**
```bash
npm install @auth0/nextjs-auth0@latest
```

Then restart the server.

### ❌ Problem 5: Port 3000 already in use

**Error:** `EADDRINUSE: address already in use :::3000`

**Solution:**
1. Stop all running terminal processes (Ctrl+C)
2. Try a different port:
   ```bash
   npm run dev -- -p 3001
   ```
3. Update `.env.local`:
   ```env
   APP_BASE_URL=http://localhost:3001
   ```
4. Update Auth0 callback URLs to use `3001` instead of `3000`

---

## **PART 10: OPTIONAL ENHANCEMENTS**

### 🔒 Enable Multi-Factor Authentication (MFA)

Make your app even more secure with 6-digit codes!

1. Go to Auth0 Dashboard
2. Click **Security → Multi-factor Auth**
3. Enable **One-time Password**
4. Set policy: **Require Multi-factor Auth → Always**
5. Click **Save**

**Test it:**
- Log out of your app
- Log in again
- You'll be asked to scan a QR code with Google Authenticator or Authy
- Enter the 6-digit code to complete login

### 📱 Add Social Login (Google, GitHub, etc.)

1. In Auth0 Dashboard, go to **Authentication → Social**
2. Click **+ Create Connection**
3. Choose **Google** (or GitHub, Facebook, etc.)
4. Follow the setup wizard
5. Enable the connection for your application

**Test it:**
- Log out
- Log in again
- You'll see a "Continue with Google" button!

---

## **PART 11: ASSIGNMENT CHECKLIST**

### ✅ Submission Requirements

Make sure you've completed:

- [ ] Auth0 account created
- [ ] Next.js app running on `localhost:3000`
- [ ] Login button works and redirects to Auth0
- [ ] Successfully logged in and see profile info
- [ ] Logout button works
- [ ] Screenshot of your logged-in page
- [ ] `.env.local` file exists (but NOT committed to GitHub!)

### 📸 Screenshots to Submit

Take screenshots of:
1. **Before login** - The page with the "Log In" button
2. **Auth0 login page** - The Auth0 Universal Login screen
3. **After login** - Your profile displayed with the "Log Out" button
4. **Auth0 Dashboard** - Your application settings page (with Client Secret hidden)

---

## **PART 12: NEXT STEPS & LEARNING RESOURCES**

### 🎓 What to Explore Next

1. **Add Protected Routes** - Make pages that only logged-in users can see
2. **Role-Based Access** - Give different permissions to different users
3. **Custom User Profiles** - Store additional user data
4. **API Routes** - Create backend endpoints that check authentication

### 📚 Helpful Resources

- **Auth0 Docs**: https://auth0.com/docs/quickstart/webapp/nextjs
- **Next.js Docs**: https://nextjs.org/docs
- **TypeScript**: https://www.typescriptlang.org/docs/

### 🆘 Getting Help

If you're stuck:
1. Check the error message carefully
2. Review the "Common Problems" section
3. Ask your instructor or TA
4. Check Auth0 Logs (Dashboard → Monitoring → Logs)

---

## **GLOSSARY - Important Terms**

| Term | Definition |
|------|------------|
| **Authentication** | The process of verifying identity (who you are) |
| **Authorization** | The process of verifying permissions (what you can do) |
| **Auth0** | A service that handles authentication for you |
| **SDK** | Software Development Kit - pre-built code to use a service |
| **Tenant** | Your private Auth0 workspace/account |
| **Client ID** | Public identifier for your app |
| **Client Secret** | Secret key (like a password) for your app |
| **Callback URL** | Where Auth0 sends users after login |
| **Session** | A period of time you stay logged in |
| **Middleware** | Code that runs before each page loads |
| **Environment Variables** | Secret configuration stored in `.env.local` |
| **localhost** | Your own computer (127.0.0.1) |
| **Port** | A number that identifies a specific application (e.g., 3000) |

---

## 🎉 Congratulations!

You've successfully built a secure authentication system! You now understand:
- How modern web authentication works
- The difference between authentication and authorization
- How to integrate third-party services (Auth0) into your apps
- How to protect user data with environment variables
- How to manage user sessions

This is a **professional-grade** authentication system used by companies worldwide!

---

## 📝 Quick Reference Commands

```bash
# Create new Next.js project
npx create-next-app@15 my-app --typescript --tailwind --app --src-dir --yes

# Install Auth0
npm install @auth0/nextjs-auth0@latest

# Start development server
npm run dev

# Generate random secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Stop server
Ctrl + C
```

---

**Remember**: Keep your `.env.local` file secret and NEVER commit it to GitHub!

Good luck! 🚀
