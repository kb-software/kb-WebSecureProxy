/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsavl03.cpp                                         |*/
/*| -------------                                                     |*/
/*|  Subroutines to arrange data objects in an avl tree structure.    |*/
/*|                                                                   |*/
/*|                                                                   |*/
/*|  Tischhöfer 15.05.07                                              |*/
/*|  last change: 18.10.12                                            |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2007,2012                                      |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

//#define TREECHECK

#include <stdarg.h>
#include <string.h>
#include "hob-avl03.h"

#ifndef TRUE
  #define TRUE 1
#endif
#ifndef FALSE
  #define FALSE 0
#endif

/**
 * AVL tree operation: rotate right at given position
 *
 * @param   struct dsd_htree1_avl_entry *adsp_node_n   entry, where balance is disturbed
 * @param   struct dsd_htree1_avl_entry *adsp_node_n1  child of n with deeper subtree
 *
 * @return  BOOL    TRUE, if n1 is new root, else FALSE
 */
static BOOL m_rot_right(dsd_htree1_avl_entry *adsp_node_n,
                        dsd_htree1_avl_entry *adsp_node_n1)
{   /* --------------------------------------------------------------------- */
    /* n  := node, where balance is disturbed                                */
    /* n1 := child of n with deeper subtree                                  */
    /* s1, s2, s3: subtrees of the nodes n, n1 (from left to right)          */
    /* new node was inserted in s1, causing a change of height               */
    /* if inserted in s2: --> see doublerot_l_r                              */
    /* --------------------------------------------------------------------- */
    /* or node was deleted in s3, causing a change of height                 */
    /* --> one additional case: bal(n1) = 0 before rotation                  */
    /* --------------------------------------------------------------------- */
    /*                 before rot_right              after rot_right         */
    /* level of n:               n                         n1                */
    /* level of n+1:        n1       s3                s1       n            */
    /* ...               s1   s2     s3                s1     s2  s3         */
    /* old bottom-1:     s1   s2     s3                s1     s2  s3         */
    /* old bottom:       s1   s2     --                s1     s2  s3         */
    /* new node:         s1   --     --                --     --  --         */
    /* --------------------------------------------------------------------- */
    /* balances:       before rot_right              after rot_right         */
    /*                   bal(n1) = -1                  bal(n1) =  0          */
    /*                   bal(n ) = -2                  bal(n ) =  0          */
    /* --------------------------------------------------------------------- */
    /* (only deletion)   bal(n1) =  0                  bal(n1) =  1          */
    /*                   bal(n ) = -2                  bal(n ) = -1          */
    /* --------------------------------------------------------------------- */

    adsp_node_n->byc_balance
        += 1 - adsp_node_n1->byc_balance;
    adsp_node_n1->byc_balance += 1;

    adsp_node_n1->adsc_parent = adsp_node_n->adsc_parent;
    adsp_node_n->adsc_parent  = adsp_node_n1;
    adsp_node_n->adsc_left    = adsp_node_n1->adsc_right;
    if (adsp_node_n->adsc_left != NULL)
      adsp_node_n->adsc_left->adsc_parent = adsp_node_n;
    adsp_node_n1->adsc_right  = adsp_node_n;

    if (adsp_node_n1->adsc_parent == 0)
      return TRUE;  /* is root */
    if (adsp_node_n1->adsc_parent->adsc_left == adsp_node_n) {
      adsp_node_n1->adsc_parent->adsc_left = adsp_node_n1;
      return FALSE;
    }
    adsp_node_n1->adsc_parent->adsc_right = adsp_node_n1;
    return FALSE;
}

/**
 * AVL tree operation: rotate left at given position
 *
 * @param   struct dsd_htree1_avl_entry *adsp_node_n   entry, where balance is disturbed
 * @param   struct dsd_htree1_avl_entry *adsp_node_n1  child of n with deeper subtree
 *
 * @return  BOOL    TRUE, if n1 is new root, else FALSE
 */
static BOOL m_rot_left(dsd_htree1_avl_entry *adsp_node_n,
                       dsd_htree1_avl_entry *adsp_node_n1)
{
    adsp_node_n->byc_balance
        -= 1 + adsp_node_n1->byc_balance;
    adsp_node_n1->byc_balance -= 1;

    adsp_node_n1->adsc_parent = adsp_node_n->adsc_parent;
    adsp_node_n->adsc_parent  = adsp_node_n1;
    adsp_node_n->adsc_right   = adsp_node_n1->adsc_left;
    if (adsp_node_n->adsc_right != NULL)
      adsp_node_n->adsc_right->adsc_parent = adsp_node_n;
    adsp_node_n1->adsc_left  = adsp_node_n;

    if (adsp_node_n1->adsc_parent == 0)
      return TRUE;   /* is root */
    if (adsp_node_n1->adsc_parent->adsc_left == adsp_node_n) {
      adsp_node_n1->adsc_parent->adsc_left = adsp_node_n1;
      return FALSE;
    }
    adsp_node_n1->adsc_parent->adsc_right = adsp_node_n1;
    return FALSE;
}

/**
 * AVL tree operation: double rotate left right at given position
 *
 * @param   struct dsd_htree1_avl_entry *adsp_node_n   entry, where balance is disturbed
 * @param   struct dsd_htree1_avl_entry *adsp_node_n1  child of n wth deeper subtree
 * @param   struct dsd_htree1_avl_entry *adsp_node_n2  child of n1 wth deeper subtree
 *
 * @return  BOOL    TRUE, if n2 is new root, else FALSE
 */
static BOOL m_doublerot_l_r(dsd_htree1_avl_entry *adsp_node_n,
                            dsd_htree1_avl_entry *adsp_node_n1,
                            dsd_htree1_avl_entry *adsp_node_n2)
{   /* --------------------------------------------------------------------- */
    /* first make rot_left for node n1 and then rot_right for node n         */
    /* --------------------------------------------------------------------- */
    /* n  := node, where balance is disturbed                                */
    /* n1 := child of n with deeper subtree                                  */
    /* n2 := child of n1 with deeper subtree                                 */
    /* s1, s2, s3, s4: subtrees of the nodes n, n1, n2 (from left to right)  */
    /* new node was inserted in s2 or s3, causing a change of height         */
    /* --------------------------------------------------------------------- */
    /* or node was deleted in s4, causing a change of height                 */
    /* --> no additional cases                                               */
    /* --------------------------------------------------------------------- */
    /*              before doublerot_l_r           after doublerot_l_r       */
    /* level of n:            n                            n2                */
    /* level of n+1:     n1         s4                n1         n           */
    /* level of n+2:  s1     n2     s4              s1  s2     s3  s4        */
    /* ...            s1   s2  s3   s4              s1  s2     s3  s4        */
    /* old bottom-1:  s1   s2  s3   s4              s1  s2     s3  s4        */
    /* old bottom:    s1   s2  s3   --              s1  s2?    s3? s4        */
    /* new node:      --   s2? s3?  --              --  --     --  --        */
    /* --------------------------------------------------------------------- */
    /* balances:    before doublerot_l_r            after doublerot_l_r      */
    /* 1)new node      bal(n2) = -1                    bal(n2) =  0          */
    /*    -->s2        bal(n1) =  1                    bal(n1) =  0          */
    /*                 bal(n ) = -2                    bal(n ) =  1          */
    /* --------------------------------------------------------------------- */
    /* 2)new node      bal(n2) =  1                    bal(n2) =  0          */
    /*    -->s3        bal(n1) =  1                    bal(n1) = -1          */
    /*                 bal(n ) = -2                    bal(n ) =  0          */
    /* --------------------------------------------------------------------- */
    /* 3)new node      bal(n2) =  0                    bal(n2) =  0          */
    /*    == n2        bal(n1) =  1                    bal(n1) =  0          */
    /*                 bal(n ) = -2                    bal(n ) =  0          */
    /* --------------------------------------------------------------------- */

    adsp_node_n->adsc_left = adsp_node_n2->adsc_right;
    if (adsp_node_n->adsc_left)
      adsp_node_n->adsc_left->adsc_parent = adsp_node_n;
    adsp_node_n1->adsc_right = adsp_node_n2->adsc_left;
    if (adsp_node_n1->adsc_right)
      adsp_node_n1->adsc_right->adsc_parent = adsp_node_n1;
    adsp_node_n2->adsc_left  = adsp_node_n1;
    adsp_node_n2->adsc_right = adsp_node_n;
    adsp_node_n2->adsc_parent = adsp_node_n->adsc_parent;
    adsp_node_n1->adsc_parent = adsp_node_n2;
    adsp_node_n->adsc_parent  = adsp_node_n2;

    /* new balances */
    if (adsp_node_n2->byc_balance < 0) {
      adsp_node_n->byc_balance  = 1;
      adsp_node_n1->byc_balance = 0;
      adsp_node_n2->byc_balance = 0;
    }
    else if (adsp_node_n2->byc_balance > 0) {
      adsp_node_n->byc_balance  = 0;
      adsp_node_n1->byc_balance = -1;
      adsp_node_n2->byc_balance =  0;
    }
    else {
      adsp_node_n->byc_balance  = 0;
      adsp_node_n1->byc_balance = 0;
    }

    if (adsp_node_n2->adsc_parent == 0)
      return TRUE;   /* is root */
    if (adsp_node_n2->adsc_parent->adsc_left == adsp_node_n) {
      adsp_node_n2->adsc_parent->adsc_left = adsp_node_n2;
      return FALSE;
    }
    adsp_node_n2->adsc_parent->adsc_right = adsp_node_n2;
    return FALSE;
}

/**
 * AVL tree operation: double rotate right left at given position
 *
 * @param   struct dsd_htree1_avl_entry *adsp_node_n   entry, where balance is disturbed
 * @param   struct dsd_htree1_avl_entry *adsp_node_n1  child of n wth deeper subtree
 * @param   struct dsd_htree1_avl_entry *adsp_node_n2  child of n1 wth deeper subtree
 *
 * @return  BOOL    TRUE, if n2 is new root, else FALSE
 */
static BOOL m_doublerot_r_l(dsd_htree1_avl_entry *adsp_node_n,
                            dsd_htree1_avl_entry *adsp_node_n1,
                            dsd_htree1_avl_entry *adsp_node_n2)
{
    adsp_node_n->adsc_right  = adsp_node_n2->adsc_left;
    if (adsp_node_n->adsc_right)
      adsp_node_n->adsc_right->adsc_parent = adsp_node_n;
    adsp_node_n1->adsc_left  = adsp_node_n2->adsc_right;
    if (adsp_node_n1->adsc_left)
      adsp_node_n1->adsc_left->adsc_parent = adsp_node_n1;
    adsp_node_n2->adsc_right = adsp_node_n1;
    adsp_node_n2->adsc_left  = adsp_node_n;
    adsp_node_n2->adsc_parent = adsp_node_n->adsc_parent;
    adsp_node_n1->adsc_parent = adsp_node_n2;
    adsp_node_n->adsc_parent  = adsp_node_n2;

    /* new balances */
    if (adsp_node_n2->byc_balance > 0) {
      adsp_node_n->byc_balance  = -1;
      adsp_node_n1->byc_balance = 0;
      adsp_node_n2->byc_balance = 0;
    }
    else if (adsp_node_n2->byc_balance < 0) {
      adsp_node_n->byc_balance  = 0;
      adsp_node_n1->byc_balance = 1;
      adsp_node_n2->byc_balance = 0;
    }
    else {
      adsp_node_n->byc_balance  = 0;
      adsp_node_n1->byc_balance = 0;
    }

    if (adsp_node_n2->adsc_parent == 0)
      return TRUE;   /* is root */
    if (adsp_node_n2->adsc_parent->adsc_left == adsp_node_n) {
      adsp_node_n2->adsc_parent->adsc_left = adsp_node_n2;
      return FALSE;
    }
    adsp_node_n2->adsc_parent->adsc_right = adsp_node_n2;
    return FALSE;
}

/**
 * Rebalance AVL tree after a delete operation
 *
 * @param   struct dsd_htree1_avl_work *adsp_work   information, where entry was deleted
 */
static void m_rebalance (dsd_htree1_avl_work *adsp_work)
{   /* rebalance the tree up to the root in case of deletion                 */
    dsd_htree1_avl_entry *adsl_entry;
    dsd_htree1_avl_entry *adsl_son;

    adsl_entry = adsp_work->adsc_found;
    if (adsp_work->imc_flag) {
      adsl_entry->byc_balance++;         /* balance after deleting           */
    }
    else {
      adsl_entry->byc_balance--;         /* balance after deleting           */
    }

    while (TRUE) {    /* loop will be left, if balanced, or if root is reached  */
      if (adsl_entry->byc_balance == 0)
      {  /* --> this subtree is now one shorter */
        if (adsl_entry->adsc_parent == NULL)
          break;   /* already at root node */
        if (adsl_entry->adsc_parent->adsc_left == adsl_entry) { /* left s. */
          adsl_entry = adsl_entry->adsc_parent;
          adsl_entry->byc_balance += 1;      /* balance moves one to right  */
          continue;
        }
        /* else, right subtree becomes shorter */
        adsl_entry = adsl_entry->adsc_parent;
        adsl_entry->byc_balance -= 1;
        continue;
      }

      if (adsl_entry->byc_balance == -2) {           /* rotate to right     */
        adsl_son = adsl_entry->adsc_left;
        if (adsl_son->byc_balance <= 0) {
          if (m_rot_right(adsl_entry, adsl_son)) {
            adsp_work->adsc_found = adsl_son;       /* new root entry      */
            return;
          }
        }
        else {
          if (m_doublerot_l_r(adsl_entry, adsl_son, adsl_son->adsc_right))
          {
            adsp_work->adsc_found = adsl_entry->adsc_parent;   /* new root  */
            return;
          }
        }
        adsl_entry = adsl_entry->adsc_parent;    /* top of rotated nodes    */

        /* If the balance at adsl_entry is zero after the rotate,
           that subtree is one shorter, i.e. balance of parent changes, if not,
           tree now is completly balanced (see graphics of rot, doublerot)   */
        if (adsl_entry->byc_balance == 0) {
          if (adsl_entry->adsc_parent->adsc_left == adsl_entry) {
            adsl_entry = adsl_entry->adsc_parent;
            adsl_entry->byc_balance += 1;    /* left subtree is shortened    */
          }
          else {
            adsl_entry = adsl_entry->adsc_parent;
            adsl_entry->byc_balance -= 1;   /* right subtree is shortened   */
          }
          continue;
        }
        /* else, tree is completely balanced */
      }
      else if (adsl_entry->byc_balance == 2) {       /* rotate to left      */
        adsl_son = adsl_entry->adsc_right;
        if (adsl_son->byc_balance >= 0) {
          if (m_rot_left(adsl_entry, adsl_son)) {
            adsp_work->adsc_found = adsl_son;       /* new root entry      */
            return;
          }
        }
        else {
          if (m_doublerot_r_l(adsl_entry, adsl_son, adsl_son->adsc_left))
          {
            adsp_work->adsc_found = adsl_entry->adsc_parent;   /* new root  */
            return;
          }
        }
        adsl_entry = adsl_entry->adsc_parent;    /* top of rotated nodes    */

        /* If the balance at adsl_entry is zero after the rotate,
           that subtree is one shorter, i.e. balance of parent changes, if not,
           tree now is completly balanced (see graphics of rot, doublerot)   */
        if (adsl_entry->byc_balance == 0) {
          if (adsl_entry->adsc_parent->adsc_left == adsl_entry) {
            adsl_entry = adsl_entry->adsc_parent;
            adsl_entry->byc_balance += 1;
          }
          else {
            adsl_entry = adsl_entry->adsc_parent;
            adsl_entry->byc_balance -= 1;
          }
          continue;
        }
        /* else, tree is completely balanced */
      }

      /* if balance is 1 or -1 the tree balance is unchanged above           */
      break;
    }

    adsp_work->adsc_found = NULL;  /* no new root entry */

    return;
}

/*---------------------------------------------------------------------------*/
/* extern routines                                                           */
/*---------------------------------------------------------------------------*/
/**
 * Initialize the avl tree control structure: struct dsd_htree1_avl_cntl 
 *
 * @param   void *ap_userfld			pass through a user dependent pointer (reserved)
 * @param   struct dsd_htree1_avl_cntl *adsp_avl_cntl   control structure for avl tree
 * @param   amd_htree1_avl_cntl amp_avl_cmp		  function pointer to compare routine
 *
 * @return  BOOL    TRUE, if initialization is successfull, else FALSE
 */
extern PTYPE BOOL m_htree1_avl_init( void *ap_userfld,
                   struct dsd_htree1_avl_cntl *adsp_avl_cntl,
                   amd_htree1_avl_cmp    amp_avl_cmp)
                   //int inp )
{
    if (adsp_avl_cntl == NULL)
      return FALSE;
    adsp_avl_cntl->amc_htree1_avl_cmp = amp_avl_cmp;   // save pointer to compare routine
    adsp_avl_cntl->adsc_root = NULL;
    //adsp_avl_cntl->imc_count = 0;

    return TRUE;
}

/**
 * Search for an entry inside the avl tree
 *
 * @param   void *ap_userfld			pass through a user dependent pointer to the compare routine
 * @param   struct dsd_htree1_avl_cntl  *adsp_avl_cntl   control structure for avl tree
 * @param   struct dsd_htree1_avl_work  *adsp_avl_work   working structure for the search
 * @param   struct dsd_htree1_avl_entry *adsp_avl_entry  data of searched entry, needed by compare routine
 *
 * @return  BOOL    FALSE in case of error, else TRUE
 */
extern PTYPE BOOL m_htree1_avl_search( void *ap_userfld,
                                 struct dsd_htree1_avl_cntl *adsp_avl_cntl,
                                 struct dsd_htree1_avl_work *adsp_avl_work,
                                 struct dsd_htree1_avl_entry *adsp_avl_entry )
{
    int inl_rc;
    dsd_htree1_avl_entry *adsl_entry;

#ifdef TREECHECK
    if ((adsp_avl_cntl == NULL) || (adsp_avl_entry == NULL) ||
        (adsp_avl_work == NULL)) {
      return FALSE;
    }
#endif

    adsl_entry = adsp_avl_cntl->adsc_root;
    if (adsl_entry == NULL) {
      adsp_avl_work->adsc_found = NULL;
      adsp_avl_work->adsc_curr_node = NULL;
      return TRUE;
    }

    while (TRUE) {   /* search entry */
#ifdef TREECHECK
      if (adsl_entry->byrc_flags[0] != 'A')
        return FALSE;
#endif
      inl_rc
          = adsp_avl_cntl->amc_htree1_avl_cmp(ap_userfld, adsp_avl_entry, adsl_entry);
      if (inl_rc > 0) {
        if (adsl_entry->adsc_right == 0) {  /* not in tree */
          adsp_avl_work->adsc_found = NULL;
          adsp_avl_work->adsc_curr_node = adsl_entry;
          adsp_avl_work->imc_flag   = 1;    /* new entry will be right son */
          break;
        }
        adsl_entry = adsl_entry->adsc_right;
        continue;
      }
      else if (inl_rc < 0) {
        if (adsl_entry->adsc_left == 0) {  /* not in tree */
          adsp_avl_work->adsc_found = NULL;
          adsp_avl_work->adsc_curr_node = adsl_entry;
          adsp_avl_work->imc_flag   = -1;  /* new entry will be left son */
          break;
        }
        adsl_entry = adsl_entry->adsc_left;
        continue;
      }
      else {  /* entry found in tree */
        adsp_avl_work->adsc_found = adsl_entry;
        adsp_avl_work->adsc_curr_node = NULL;
        break;
      }
    }

    return TRUE;
}

/**
 * Insert an entry into the avl tree
 *
 * @param   void *ap_userfld			pass through a user dependent pointer (reserved)
 * @param   struct dsd_htree1_avl_cntl  *adsp_avl_cntl   control structure for avl tree
 * @param   struct dsd_htree1_avl_work  *adsp_avl_work   contains information from previous search
 * @param   struct dsd_htree1_avl_entry *adsp_avl_entry  data structure to insert into avl tree
 *
 * @return  BOOL    FALSE in case of error, else TRUE
 */
extern PTYPE BOOL m_htree1_avl_insert( void *ap_userfld,
                                  struct dsd_htree1_avl_cntl *adsp_avl_cntl,
                                  struct dsd_htree1_avl_work *adsp_avl_work,
                                  struct dsd_htree1_avl_entry *adsp_avl_entry )
{
    dsd_htree1_avl_entry *adsl_entry;
    dsd_htree1_avl_entry *adsl_parent;

#ifdef TREECHECK
    if ((adsp_avl_cntl == NULL) || (adsp_avl_entry == NULL) ||
        (adsp_avl_work == NULL) || (adsp_avl_work->adsc_found != NULL) )
    {
      return FALSE;
    }
#endif

    adsl_entry = adsp_avl_work->adsc_curr_node; /* from m_htree1_avl_search()*/
    if (adsl_entry == NULL) {   /* insert first entry   */
      if (adsp_avl_cntl->adsc_root != NULL)
        return FALSE;
      memset(adsp_avl_entry, 0, sizeof(dsd_htree1_avl_entry));
      adsp_avl_cntl->adsc_root = adsp_avl_entry;
#ifdef TREECHECK
      adsp_avl_entry->byrc_flags[0] = 'A';
#endif
      //adsp_avl_cntl->imc_count++;

      return TRUE;
    }

    /* insert new entry at position determined by m_htree1_avl_search() */
    adsp_avl_entry->adsc_parent = adsl_entry;
    adsp_avl_entry->adsc_left   = NULL;
    adsp_avl_entry->adsc_right  = NULL;
    adsp_avl_entry->byc_balance = 0;

    if (adsp_avl_work->imc_flag > 0) {
      adsl_entry->byc_balance += 1;
      adsl_entry->adsc_right  = adsp_avl_entry;
    }
    else {
      adsl_entry->byc_balance -= 1;
      adsl_entry->adsc_left   = adsp_avl_entry;
    }
#ifdef TREECHECK
      adsp_avl_entry->byrc_flags[0] = 'A';  /* write testbyte */
#endif

    /* rebalance avl tree */
    if (adsl_entry->byc_balance == 0)
    { /* tree is completely balanced above */
      //adsp_avl_cntl->imc_count++;
      return TRUE;
    }

    adsl_parent = adsl_entry->adsc_parent;
    while (adsl_parent) {
      if (adsl_parent->adsc_right == adsl_entry)
        adsl_parent->byc_balance += 1;       /* right subtree has grown      */
      else
        adsl_parent->byc_balance -= 1;       /* left subtree has grown       */

      if (adsl_parent->byc_balance == 0)
      { /* tree is completely balanced above */
        //adsp_avl_cntl->imc_count++;
        return TRUE;
      }

      /* |balance| == 2 --> need to correct balance by rotations             */
      /* after rotations, tree is completely balanced                        */
      if (adsl_parent->byc_balance == -2) {        /* rotate to right        */
        if (adsl_entry->byc_balance <= 0) {
          if (m_rot_right(adsl_parent, adsl_entry))
            adsp_avl_cntl->adsc_root = adsl_entry;    /* new root entry      */
        }
        else {
          if (m_doublerot_l_r(adsl_parent, adsl_entry, adsl_entry->adsc_right))
            adsp_avl_cntl->adsc_root = adsl_parent->adsc_parent; /* new root */
        }
        //adsp_avl_cntl->imc_count++;

        return TRUE;
      }
      if (adsl_parent->byc_balance == 2) {         /* rotate to left         */
        if (adsl_entry->byc_balance >= 0) {
          if (m_rot_left(adsl_parent, adsl_entry))
            adsp_avl_cntl->adsc_root = adsl_entry;    /* new root entry      */
        }
        else {
          if (m_doublerot_r_l(adsl_parent, adsl_entry, adsl_entry->adsc_left))
            adsp_avl_cntl->adsc_root = adsl_parent->adsc_parent; /* new root */
        }
        //adsp_avl_cntl->imc_count++;

        return TRUE;
      }

      adsl_entry  = adsl_parent;
      adsl_parent = adsl_parent->adsc_parent;
    }
    //adsp_avl_cntl->imc_count++;

    return TRUE;
}

/**
 * Get next element in ascending order to a previous tree operation (search, delete, getnext),
 * or get first element, if bop_first_entry is TRUE
 *
 * @param   void *ap_userfld			  pass through a user dependent pointer (reserved)
 * @param   struct dsd_htree1_avl_cntl  *adsp_avl_cntl   control structure for avl tree
 * @param   struct dsd_htree1_avl_work  *adsp_avl_work   contains information from previous tree operation
 * @param   BOOL bop_first_entry    if set to TRUE, get first element of tree
 *
 * @return  BOOL    FALSE in error case, else TRUE
 */
extern PTYPE BOOL m_htree1_avl_getnext( void *ap_userfld,
                                        struct dsd_htree1_avl_cntl *adsp_cntl,
                                        struct dsd_htree1_avl_work *adsp_work,
                                        BOOL bop_first_entry )
{
    dsd_htree1_avl_entry *adsl_root;
    dsd_htree1_avl_entry *adsl_entry;

#ifdef TREECHECK
    if ((adsp_cntl == NULL) || (adsp_work == NULL)) {
      return FALSE;
    }
#endif

    adsl_root = adsp_cntl->adsc_root;
    if (adsl_root == NULL) {   /* no entries in tree     */
      adsp_work->adsc_found = NULL;
      return TRUE;
    }

    if (bop_first_entry) {   /* search for smallest entry */
      adsl_entry = adsl_root;
#ifdef TREECHECK
      if (adsl_entry->byrc_flags[0] != 'A')
        return FALSE;
#endif
      while (adsl_entry->adsc_left != NULL) {
        adsl_entry = adsl_entry->adsc_left;
#ifdef TREECHECK
        if (adsl_entry->byrc_flags[0] != 'A')
          return FALSE;
#endif
      }
      adsp_work->adsc_found = adsl_entry;
        return TRUE;
    }

    adsl_entry = adsp_work->adsc_found;  /* get next to this entry */
    if (adsl_entry == NULL) {
      adsl_entry = adsp_work->adsc_curr_node;  /* set by m_htree1_avl_delete() */
      adsp_work->adsc_curr_node = NULL;
      if (adsl_entry == NULL)
        return FALSE;  /* error in calling getnext */
#ifdef TREECHECK
      if (adsl_entry->byrc_flags[0] != 'A')
        return FALSE;
#endif
      if (adsp_work->imc_flag < 0) {   /* this is next to the deleted entry  */
        adsp_work->adsc_found = adsl_entry;
        return TRUE;
      }
      /* else, search for next bigger entry */
    }

    /* if right subtree, next is the most left one of the right subtree */
    if (adsl_entry->adsc_right != NULL) {
      adsl_entry = adsl_entry->adsc_right;
      while (adsl_entry->adsc_left != NULL) {
        adsl_entry = adsl_entry->adsc_left;
#ifdef TREECHECK
      if (adsl_entry->byrc_flags[0] != 'A')
        return FALSE;
#endif
      }
      adsp_work->adsc_found = adsl_entry;

      return TRUE;
    }

    /* else, search for an upper node, to which the entry is on the left     */
    while (adsl_entry->adsc_parent != NULL) {
#ifdef TREECHECK
      if (adsl_entry->adsc_parent->byrc_flags[0] != 'A')
        return FALSE;
#endif
      if (adsl_entry->adsc_parent->adsc_left == adsl_entry) {
        adsp_work->adsc_found = adsl_entry->adsc_parent;
        return TRUE;
      }
      adsl_entry = adsl_entry->adsc_parent;
    }

    /* no bigger entry is in the tree */
    adsp_work->adsc_found = NULL;
    return TRUE;
}

/**
 * Remove an entry from the avl tree
 *
 * @param   void *ap_userfld			pass through a user dependent pointer (reserved)
 * @param   struct dsd_htree1_avl_cntl  *adsp_avl_cntl   control structure for avl tree
 * @param   struct dsd_htree1_avl_work  *adsp_avl_work   information, which entry should be removed
 *
 * @return  BOOL    FALSE in error case, else TRUE
 */
extern PTYPE BOOL m_htree1_avl_delete( void *ap_userfld,
                                       struct dsd_htree1_avl_cntl *adsp_cntl,
                                       struct dsd_htree1_avl_work *adsp_work )
{
    dsd_htree1_avl_entry *adsl_entry_del;        /* entry to delete            */
    dsd_htree1_avl_entry *adsl_entry_next;       /* next bigger to the deleted */
    dsd_htree1_avl_entry *adsl_start_balance;    /* where to start balancing   */
    int iml_flag;

#ifdef TREECHECK
    if ((adsp_cntl == NULL) || (adsp_work == NULL)) {
      return FALSE;
    }
#endif

    adsl_entry_del  = adsp_work->adsc_found;
    if ((adsp_cntl->adsc_root == NULL) || (adsl_entry_del == NULL)) {
      return FALSE;   /* nothing to delete */
    }
#ifdef TREECHECK
    if (adsl_entry_del->byrc_flags[0] != 'A')
      return FALSE;
    adsl_entry_del->byrc_flags[0] = 0;   /* no longer an entry */
#endif
    //adsp_cntl->imc_count--;  /* update element counter */

    /* if the entry has no right son, replace it with its left son,
     if it has one, and rebalance the tree, beginning with parent
     of the entry, upwards to the root.                                      */
    if (adsl_entry_del->adsc_right == NULL) {
      if (adsl_entry_del->adsc_parent == NULL) { /* tree has only 1 or 2 entries */
        adsp_work->adsc_curr_node  /* for getnext */
                 = adsp_cntl->adsc_root = adsl_entry_del->adsc_left;
        if (adsp_cntl->adsc_root != NULL) {
          adsp_cntl->adsc_root->adsc_parent = NULL;
          adsp_work->imc_flag = 1; /* getnext: next is next of adsc_curr_node */
        }
        adsp_work->adsc_found = NULL;      /* for getnext     */

        return TRUE;
      }
#ifdef TREECHECK
      if (adsl_entry_del->adsc_parent->byrc_flags[0] != 'A')
        return FALSE;
#endif
      adsl_start_balance = adsl_entry_del->adsc_parent;
      if (adsl_start_balance->adsc_left == adsl_entry_del) {  /* left subtr.  */
        adsl_start_balance->adsc_left = adsl_entry_del->adsc_left;
        if (adsl_start_balance->adsc_left != NULL)
          adsl_start_balance->adsc_left->adsc_parent = adsl_start_balance;
        adsp_work->imc_flag = 1;
        adsp_work->adsc_curr_node = adsl_start_balance;       /* for getnext */
        iml_flag = -1;                  /* getnext: next is adsc_curr_node   */
      }
      else {   /* right subtree shortened */
        adsl_start_balance->adsc_right = adsl_entry_del->adsc_left;
        if (adsl_start_balance->adsc_right != NULL) {
          adsp_work->adsc_curr_node
                          = adsl_start_balance->adsc_right;   /* for getnext */
          adsl_start_balance->adsc_right->adsc_parent = adsl_start_balance;
        }
        else {
          adsp_work->adsc_curr_node = adsl_start_balance;     /* for getnext */
        }
        adsp_work->imc_flag = 0;
        iml_flag = 1;          /* get_next: next is next of adsc_curr_node   */
      }
      adsp_work->adsc_found = adsl_start_balance;     /* for m_rebalance()   */
    }

    /* if the entry has a right son, replace it with the next bigger
       entry (the most left one in the right subtree) := next_entry.
       If next_entry has a right son, replace its old place with
       that son. Then rebalance the tree, beginning with the old parent
       of next_entry, upwards until the root.                                */
    else {
      adsl_entry_next = adsl_entry_del->adsc_right;
      if (adsl_entry_next->adsc_left == NULL)
      { /* adsl_entry_next was right son of adsl_entry_del */
#ifdef TREECHECK
        if (adsl_entry_next->byrc_flags[0] != 'A')
          return FALSE;
#endif
        /* prepare for get_next */
        adsp_work->adsc_curr_node = adsl_entry_next;
        iml_flag = -1;    /* get_next: next is adsc_curr_node */

        /* replace entry to delete with right son */
        adsl_entry_next->adsc_parent = adsl_entry_del->adsc_parent;
        if (adsl_entry_del->adsc_left != NULL) { /* left son could have sons */
          adsl_entry_next->adsc_left = adsl_entry_del->adsc_left;
          adsl_entry_next->adsc_left->adsc_parent = adsl_entry_next;
          adsl_entry_next->byc_balance = adsl_entry_del->byc_balance;
          adsl_start_balance  = adsl_entry_next;
          adsp_work->imc_flag = 0;    /* right subtree was shortened   */
          if (adsl_entry_next->adsc_parent == 0) {
            adsp_cntl->adsc_root = adsl_entry_next;      /* new root   */
          }
          else {
            if (adsl_entry_next->adsc_parent->adsc_left == adsl_entry_del)
              adsl_entry_next->adsc_parent->adsc_left = adsl_entry_next;
            else
              adsl_entry_next->adsc_parent->adsc_right = adsl_entry_next;
          }
        }
        else {  /* deleted entry has no left son */
          if (adsl_entry_next->adsc_parent == NULL) {
            adsp_cntl->adsc_root = adsl_entry_next;
            adsp_work->imc_flag = iml_flag; /* getnext: next is adsc_curr_node */
            adsp_work->adsc_found = 0;      /* for getnext   */

            return TRUE;
          }
          adsl_start_balance = adsl_entry_next->adsc_parent;
          if (adsl_start_balance->adsc_left == adsl_entry_del) {
            adsl_start_balance->adsc_left = adsl_entry_next;
            adsp_work->imc_flag = 1;    /* left subtree was shortened   */
          }
          else {
            adsl_start_balance->adsc_right = adsl_entry_next;
            adsp_work->imc_flag = 0;    /* right subtree was shortened  */
          }
        }
      } /* end adsl_next_entry was right son */
      else {  /* right son has a left son */
        do {  /* get the most left in that subtree */
          adsl_entry_next = adsl_entry_next->adsc_left;
        } while (adsl_entry_next->adsc_left != NULL);
#ifdef TREECHECK
        if (adsl_entry_next->byrc_flags[0] != 'A')
          return FALSE;
#endif
        /* prepare for get_next */
        adsp_work->adsc_curr_node = adsl_entry_next;
        iml_flag = -1;    /* getnext: next is adsc_curr_node */

        adsl_start_balance = adsl_entry_next->adsc_parent;
        adsl_start_balance->adsc_left = adsl_entry_next->adsc_right;
        if (adsl_start_balance->adsc_left != NULL)
          adsl_start_balance->adsc_left->adsc_parent = adsl_start_balance;
        adsp_work->imc_flag = 1;      /* left subtree was shortened          */

        /* replace entry to delete with this entry                           */
        adsl_entry_next->adsc_left   = adsl_entry_del->adsc_left;
        adsl_entry_next->adsc_right  = adsl_entry_del->adsc_right;
        adsl_entry_next->adsc_parent = adsl_entry_del->adsc_parent;
        adsl_entry_next->byc_balance = adsl_entry_del->byc_balance;
        adsl_entry_next->adsc_left->adsc_parent  = adsl_entry_next;
        adsl_entry_next->adsc_right->adsc_parent = adsl_entry_next;

        if (adsl_entry_next->adsc_parent != NULL) {
          if (adsl_entry_next->adsc_parent->adsc_left == adsl_entry_del) {
            adsl_entry_next->adsc_parent->adsc_left = adsl_entry_next;
          }
          else {
            adsl_entry_next->adsc_parent->adsc_right = adsl_entry_next;
          }
        }
        else {  /* deleted entry was root */
          adsp_cntl->adsc_root = adsl_entry_next;
        }
      }
      adsp_work->adsc_found = adsl_start_balance;
    }

    /* adsp_work is used to pass parameters and get the new root, if changed */
    m_rebalance(adsp_work);   /* returns new root in adsp-work->adsc_found   */

    if (adsp_work->adsc_found != NULL) {
      adsp_cntl->adsc_root = adsp_work->adsc_found;     /* tree has new root */
      adsp_work->adsc_found = NULL;   /* for getnext */
    }
    adsp_work->imc_flag = iml_flag;   /* for getnext */

    return TRUE;
}


//extern PTYPE int avl_get_count( struct dsd_htree1_avl_cntl *adsp_cntl )
//{
//    return adsp_cntl->imc_count;
//}


