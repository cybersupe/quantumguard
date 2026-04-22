import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithPopup } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyDPAkvvr2d3r1Q1X-d_66mATWuM-odC_uc",
  authDomain: "quantumguard-1deb6.firebaseapp.com",
  projectId: "quantumguard-1deb6",
  storageBucket: "quantumguard-1deb6.firebasestorage.app",
  messagingSenderId: "935526339089",
  appId: "1:935526339089:web:52d19bb016cca3dd5757b0"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();
export const signInWithGoogle = () => signInWithPopup(auth, googleProvider);