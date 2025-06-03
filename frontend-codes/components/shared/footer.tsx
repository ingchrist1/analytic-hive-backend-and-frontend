import Link from 'next/link'
import React from 'react'
import Image from 'next/image';
interface FooterLink {
    title: string;
    href: string;
}
interface iconsProps{
    src:string;
    href:string
    
}

const footerLinks: FooterLink[] = [
    {
        title: 'School of Artificial Intelligence',
        href: '/'
    },
    {
        title: 'School of Data Science',
        href: '/'
    },
    {
        title: 'School of Programming',
        href: '/'
    },
    {
        title: 'School of Cloud Computing',
        href: '/'
    },
    {
        title: 'School of Cyber Security',
        href: '/'
    },
    {
        title: 'School of Digital Marketing',
        href: '/'
    },
    
]
const programs: FooterLink[] = [
    {
        title: 'Business Analytics',
        href: '/'
    },
    {
        title: 'SQL',
        href: '/'
    },
    {
        title: 'Cloud Architect',
        href: '/'
    },
    {
        title: 'Robotics',
        href: '/'
    },
    {
        title: 'Self Driving Cars',
        href: '/'
    },
    {
        title: 'AWS',
        href: '/'
    },
    
]


const icons:iconsProps[]= [
    { 
        src:"/assets/flogo.png",
        href:"/",

    },
    { 
        src:"/assets/xlogo.png",
        href:"/",

    },
    { 
        src:"/assets/linkedinlogo.png",
        href:"/",

    },
] 



const Footer = () => {
  return (
    <>
    <div className='flex flex-col gap-8'>
    <main className='flex flex-col lg:justify-between items-center  text-white'>
      <section className='flex flex-col gap-4'>
        <Image src={"/assets/Analytix Hive Logo 3.png"}  alt='Analytix Logo' width={100} height={100}/>
        <h1>
            Transforming Learning in Africa
        </h1>
        <p>
            Follow us
        </p>
        <div className='flex gap-2'>
            {icons.map((icon, index) => (
              
                    <Link href={icon.href} key={index}>
                    <Image src={icon.src} alt='logos'/>
                    </Link>
              
            ))}
        </div>
      
      </section>


      <section className='flex flex-col gap-4'>
        <h1 className='' >
         Analytix Hive Schools
        </h1>
        <ul className='flex flex-col gap-2 text-white/70'>
            {footerLinks.map((link, index) => (
                <li key={index}>
                    <Link href={link.href}>{link.title}</Link>
                </li>
            ))}
        </ul>
      </section>
      <section className='flex flex-col gap-4 '>
        <h1 className='' >
         Featured Programs
        </h1>
        <ul className='flex flex-col gap-2 text-white/70'>
            {programs.map((link, index) => (
                <li key={index}>
                    <Link href={link.href}>{link.title}</Link>
                </li>
            ))}
        </ul>
      </section>
      <section className='flex flex-col gap-4'>
        <h1 className='' >
         Company
        </h1>
        <ul className='flex flex-col gap-2 text-white/70'>
            {programs.map((link, index) => (
                <li key={index}>
                    <Link href={link.href}>{link.title}</Link>
                </li>
            ))}
        </ul>
      </section>
     
    </main>
    
    </div>
    </>
  )
}

export default Footer